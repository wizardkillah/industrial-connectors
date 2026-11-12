"""Self-contained tests: a fake BACnet device (UDP) and a fake MC-1E PLC (TCP) on loopback."""
import socket
import struct
import sys
import threading
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from bacnet import BacnetClient                       # noqa: E402
from mitsubishi_mc import McClient, McError, parse_device   # noqa: E402
from sauter_moduweb import ModuWebClient, ModuWebError      # noqa: E402


# ------------------------------------------------------------------ BACnet ---

def _complex_ack(obj_type, instance, prop, value_tags: bytes, invoke=1, routed=False) -> bytes:
    oid = struct.pack(">I", (obj_type << 22) | instance)
    apdu = bytes([0x30, invoke, 0x0C, 0x0C]) + oid + bytes([0x19, prop, 0x3E]) + value_tags + bytes([0x3F])
    # routed=True: NPDU carries a source address (SNET=1234, SLEN=1, SADR=7), as replies from behind a router do
    npdu = bytes([0x01, 0x08, 0x04, 0xD2, 0x01, 0x07]) if routed else bytes([0x01, 0x00])
    return bytes([0x81, 0x0A]) + struct.pack(">H", 4 + len(npdu) + len(apdu)) + npdu + apdu


@pytest.fixture
def bacnet_device():
    srv = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    srv.bind(("127.0.0.1", 0))
    srv.settimeout(2)
    port = srv.getsockname()[1]

    def serve():
        try:
            while True:
                data, addr = srv.recvfrom(1500)
                prop = data[-1]
                inv = data[8]                        # echo the request's invoke id
                oid = struct.unpack(">I", data[11:15])[0]
                otype, inst = oid >> 22, oid & 0x3FFFFF
                if prop == 85:                       # present-value -> REAL 12.5
                    reply = _complex_ack(otype, inst, prop, b"\x44" + struct.pack(">f", 12.5), inv)
                elif prop == 117:                    # units -> enumerated 55 (bar)
                    reply = _complex_ack(otype, inst, prop, b"\x91\x37", inv)
                elif prop == 77:                     # object-name -> "TK-01"
                    reply = _complex_ack(otype, inst, prop, bytes([0x75, 6, 0]) + b"TK-01", inv)
                else:
                    continue
                if inst == 99:                       # a late reply to an earlier request arrives first
                    stale = _complex_ack(otype, inst, prop, b"\x44" + struct.pack(">f", -1.0), (inv + 100) % 255)
                    srv.sendto(stale, addr)
                srv.sendto(reply, addr)
        except OSError:
            pass

    t = threading.Thread(target=serve, daemon=True)
    t.start()
    yield port
    srv.close()


def test_bacnet_read_property(bacnet_device):
    with BacnetClient(timeout=1.0, port=bacnet_device) as c:
        assert c.read("127.0.0.1", "analogInput", 1) == 12.5
        assert c.read("127.0.0.1", "analogInput", 1, "units") == "bar"
        assert c.read("127.0.0.1", "analogInput", 1, "object-name") == "TK-01"


def test_bacnet_ignores_stale_reply_with_other_invoke_id(bacnet_device):
    with BacnetClient(timeout=1.0, port=bacnet_device) as c:
        assert c.read("127.0.0.1", "analogInput", 99) == 12.5      # not the stale -1.0


def test_bacnet_decodes_routed_npdu():
    pkt = _complex_ack(0, 1, 85, b"D" + struct.pack(">f", 3.5), routed=True)
    assert BacnetClient.decode_value(pkt) == ("float", 3.5)


def test_bacnet_object_id_containing_0x3e_is_not_mistaken_for_tag():
    pkt = _complex_ack(0, 0x3E, 85, b"D" + struct.pack(">f", 1.25))   # instance byte 0x3E
    assert BacnetClient.decode_value(pkt) == ("float", 1.25)


def test_bacnet_boolean_value_is_in_the_tag():
    assert BacnetClient.decode_value(_complex_ack(3, 1, 85, b"")) == ("bool", True)
    assert BacnetClient.decode_value(_complex_ack(3, 1, 85, b"")) == ("bool", False)


def test_bacnet_units_follow_ashrae_135():
    from bacnet.client import UNITS
    assert (UNITS[62], UNITS[64], UNITS[98], UNITS[55], UNITS[19], UNITS[48]) == ("degC", "degF", "%", "bar", "kWh", "kW")


def test_bacnet_packet_layout():
    c = BacnetClient()
    pkt = c.build_read_property(0, 7, 85)
    assert pkt[:2] == b"\x81\x0a" and struct.unpack(">H", pkt[2:4])[0] == len(pkt)
    assert struct.unpack(">I", pkt[11:15])[0] == (0 << 22) | 7
    c.close()


def test_bacnet_rejects_bad_ip():
    with BacnetClient() as c:
        with pytest.raises(ValueError):
            c.read("not-an-ip", "analogInput", 1)


def test_bacnet_timeout_returns_none():
    with BacnetClient(timeout=0.2, port=9) as c:           # nothing listens
        assert c.read("127.0.0.1", "analogInput", 1) is None


# ------------------------------------------------------------------ MC 1E ----

class FakePlc:
    def __init__(self):
        self.words = {104: 4321, 8280: 793, 100: 0xF5C3, 101: 0x4048}      # D100..101 = 3.14 float
        self.bits = {("Y", 8): True, ("Y", 9): False, ("M", 60): True}
        self.srv = socket.socket()
        self.srv.bind(("127.0.0.1", 0))
        self.srv.listen(1)
        self.port = self.srv.getsockname()[1]
        threading.Thread(target=self._run, daemon=True).start()

    def _run(self):
        try:
            conn, _ = self.srv.accept()
        except OSError:
            return
        with conn:
            while True:
                hdr = conn.recv(12)
                if len(hdr) < 12:
                    return
                sub, head = hdr[0], struct.unpack("<I", hdr[4:8])[0]
                name = bytes([hdr[9], hdr[8]]).decode().strip()
                pts = hdr[10] or 256              # 256 points travel as 0
                if sub == 0x01:
                    out = b"".join(struct.pack("<H", self.words.get(head + i, 0)) for i in range(pts))
                    conn.sendall(bytes([0x81, 0x00]) + out)
                elif sub == 0x00:
                    vals = [self.bits.get((name, head + i), False) for i in range(pts)]
                    packed = bytearray((pts + 1) // 2)
                    for i, v in enumerate(vals):
                        packed[i // 2] |= (0x10 if v else 0) if i % 2 == 0 else (0x01 if v else 0)
                    conn.sendall(bytes([0x80, 0x00]) + bytes(packed))
                elif sub == 0x03:
                    data = conn.recv(pts * 2)
                    for i in range(pts):
                        self.words[head + i] = struct.unpack("<H", data[2 * i:2 * i + 2])[0]
                    conn.sendall(bytes([0x83, 0x00]))
                elif sub == 0x0F:                    # error that has NO abnormal-code byte
                    conn.sendall(bytes([0x8F, 0x10]))
                else:
                    conn.sendall(bytes([sub | 0x80, 0x5B, 0x10]))


def test_parse_device_octal_xy():
    assert parse_device("D104") == ("D", 104)
    assert parse_device("Y10") == ("Y", 8)
    with pytest.raises(ValueError):
        parse_device("Q5")


def test_mc_read_write_roundtrip():
    plc = FakePlc()
    with McClient("127.0.0.1", plc.port) as c:
        assert c.read_words("D104")[0] == 4321
        assert c.read_words("D8280")[0] == 793
        assert c.read_bits("Y10", 2) == [True, False]
        assert round(c.read_float("D100"), 2) == 3.14
        c.write_words("D200", [7, 8])
        assert c.read_words("D200", 2) == [7, 8]


def test_mc_rejects_wrong_device_kind():
    plc = FakePlc()
    with McClient("127.0.0.1", plc.port) as c:
        with pytest.raises(ValueError):
            c.read_bits("D100")
        with pytest.raises(ValueError):
            c.read_words("Y0")
        with pytest.raises(ValueError):
            c.read_words("D0", 100000)


def test_mc_error_code():
    plc = FakePlc()
    with McClient("127.0.0.1", plc.port) as c:
        with pytest.raises(McError) as e:
            c._exchange(bytes([0x09, 0xFF, 0x10, 0, 0, 0, 0, 0, 0x20, 0x44, 1, 0]), 0)
        assert e.value.end_code == 0x5B and e.value.abnormal == 0x10


# ---------------------------------------------------------------- moduWeb ----

def test_moduweb_requires_host_and_blocks_public_http(monkeypatch):
    monkeypatch.delenv("MODUWEB_HOST", raising=False)
    with pytest.raises(ModuWebError):
        ModuWebClient()
    with pytest.raises(ModuWebError):
        ModuWebClient(host="example.com")            # public host over HTTP
    assert ModuWebClient(host="192.0.2.1").base == "http://192.0.2.1"
    assert ModuWebClient(host="example.com", https=True).base == "https://example.com"


def test_moduweb_requires_credentials(monkeypatch):
    monkeypatch.delenv("MODUWEB_USER", raising=False)
    monkeypatch.delenv("MODUWEB_PASS", raising=False)
    with pytest.raises(ModuWebError):
        ModuWebClient(host="127.0.0.1").login()


def test_moduweb_blocks_offhost_paths():
    c = ModuWebClient(host="127.0.0.1")
    with pytest.raises(ModuWebError):
        c.fetch("http://evil.example/")


def test_mc_max_points_roundtrip():
    plc = FakePlc()
    with McClient("127.0.0.1", plc.port) as c:
        assert len(c.read_words("D0", 256)) == 256
        assert len(c.read_bits("M0", 256)) == 256


def test_mc_error_without_abnormal_code_does_not_hang_or_desync():
    plc = FakePlc()
    with McClient("127.0.0.1", plc.port, timeout=1.0) as c:
        with pytest.raises(McError) as e:
            c._exchange(bytes([0x0F, 0xFF, 0x10, 0, 0, 0, 0, 0, 0x20, 0x44, 1, 0]), 0)
        assert e.value.end_code == 0x10 and e.value.abnormal is None
        assert c.read_words("D104")[0] == 4321          # stream still in sync
