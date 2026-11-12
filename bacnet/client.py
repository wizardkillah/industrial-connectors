"""Minimal BACnet/IP client over raw UDP sockets (port 47808). No dependencies.

Implements just what a monitoring dashboard needs:

* ReadProperty (present-value, object-name, units, description, status-flags)
* Who-Is / I-Am discovery

Wire format (all big-endian)::

    BVLC (4)   0x81 | function | length(2)
    NPDU (2)   version 0x01 | control
    APDU       PDU type/flags | max-segs/apdu | invoke-id | service | tagged params

Object identifier = (object_type << 22) | instance.
"""
from __future__ import annotations

import ipaddress
import socket
import struct
import time

BACNET_PORT = 47808

OBJECT_TYPES = {
    "analogInput": 0, "analogOutput": 1, "analogValue": 2,
    "binaryInput": 3, "binaryOutput": 4, "binaryValue": 5,
    "device": 8, "multiStateValue": 19,
}
PROPERTIES = {
    "present-value": 85, "object-name": 77, "units": 117,
    "description": 28, "status-flags": 111,
}
# Subset of BACnetEngineeringUnits (ASHRAE 135, clause 21 / Annex L).
UNITS = {
    0: "m2", 2: "mA", 3: "A", 5: "V", 6: "kV", 19: "kWh", 27: "Hz",
    29: "%RH", 31: "m", 47: "W", 48: "kW", 53: "Pa", 54: "kPa", 55: "bar",
    62: "degC", 64: "degF", 71: "h", 72: "min", 73: "s", 80: "m3", 82: "L",
    85: "m3/s", 87: "L/s", 88: "L/min", 95: "", 96: "ppm", 98: "%",
    104: "rpm", 133: "hPa", 134: "mbar", 135: "m3/h", 146: "MWh",
}


class BacnetError(Exception):
    pass


class BacnetClient:
    """One UDP socket per instance. Not thread-safe: use one client per thread."""

    def __init__(self, local_ip: str | None = None, timeout: float = 1.0, port: int = BACNET_PORT):
        self.port = port
        self.timeout = timeout
        self._invoke_id = 0
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        if local_ip:
            ipaddress.ip_address(local_ip)             # validate, raises ValueError
            self.sock.bind((local_ip, 0))
        self.sock.settimeout(timeout)

    def close(self) -> None:
        try:
            self.sock.close()
        except OSError:
            pass

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()

    # ------------------------------------------------------------------ encode

    def build_read_property(self, obj_type: int, instance: int, prop_id: int) -> bytes:
        self._invoke_id = (self._invoke_id + 1) % 255
        object_id = struct.pack(">I", (obj_type << 22) | (instance & 0x3FFFFF))
        apdu = bytes([0x00, 0x05, self._invoke_id, 0x0C, 0x0C]) + object_id + bytes([0x19, prop_id])
        npdu = bytes([0x01, 0x04])                      # expecting reply
        return bytes([0x81, 0x0A]) + struct.pack(">H", 4 + len(npdu) + len(apdu)) + npdu + apdu

    @staticmethod
    def build_who_is() -> bytes:
        # BVLC broadcast NPDU (global broadcast) + unconfirmed Who-Is
        return bytes([0x81, 0x0B, 0x00, 0x0C, 0x01, 0x20, 0xFF, 0xFF, 0x00, 0xFF, 0x10, 0x08])

    # ------------------------------------------------------------------ decode

    @staticmethod
    def _apdu_offset(data: bytes) -> int | None:
        """Offset of the APDU inside a BVLC+NPDU frame, honouring routed NPDUs."""
        if len(data) < 7 or data[0] != 0x81:
            return None
        control = data[5]
        pos = 6
        if control & 0x20:                              # DNET/DLEN/DADR present
            if len(data) < pos + 3:
                return None
            pos += 3 + data[pos + 2]
        if control & 0x08:                              # SNET/SLEN/SADR present
            if len(data) < pos + 3:
                return None
            pos += 3 + data[pos + 2]
        if control & 0x20:                              # hop count
            pos += 1
        return pos if pos < len(data) else None

    @classmethod
    def _value_start(cls, data: bytes) -> int | None:
        """Index of the opening tag 3 (0x3E) of a ReadProperty ComplexACK, or None.

        Walks the ACK header (object id, property id, optional array index)
        instead of scanning for 0x3E, which can also appear inside the object id.
        """
        a = cls._apdu_offset(data)
        if a is None or len(data) < a + 5 or (data[a] & 0xF8) != 0x30:   # ComplexACK, unsegmented
            return None
        pos = a + 3                                     # type | invoke id | service
        if data[pos] != 0x0C:                           # context 0, length 4: object id
            return None
        pos += 5
        for ctx in (0x18, 0x28):                        # context 1 property id, context 2 array index
            if pos < len(data) and (data[pos] & 0xF8) == ctx:
                pos += 1 + (data[pos] & 0x07)
            elif ctx == 0x18:
                return None
        return pos if pos < len(data) and data[pos] == 0x3E else None

    @classmethod
    def decode_value(cls, data: bytes):
        """Return (kind, value) from a ComplexACK, or (None, None)."""
        i = cls._value_start(data) if data else None
        if i is None or i + 1 >= len(data):
            return None, None
        tag = data[i + 1]
        number, length = (tag >> 4) & 0xF, tag & 0x7
        if number == 1:                                 # boolean: the value lives in the tag itself
            return "bool", bool(length)
        start = i + 2
        if length == 5 and i + 2 < len(data):           # extended length
            length, start = data[i + 2], i + 3
        if number == 4 and length == 4 and len(data) >= start + 4:
            return "float", round(struct.unpack(">f", data[start:start + 4])[0], 3)
        if number == 9 and length == 1 and len(data) >= start + 1:
            return "enum", data[start]
        if number == 2 and 0 < length <= 4 and len(data) >= start + length:
            return "uint", int.from_bytes(data[start:start + length], "big")
        return None, None

    @classmethod
    def decode_text(cls, data: bytes) -> str | None:
        i = cls._value_start(data) if data else None
        if i is None or i + 1 >= len(data):
            return None
        j = i + 1
        length = data[j] & 0x7
        if length == 5 and j + 1 < len(data):
            length, start = data[j + 1], j + 2
        else:
            start = j + 1
        if start >= len(data):
            return None
        charset = data[start]
        raw = data[start + 1:start + length]
        encoding = "utf-8" if charset == 0 else "utf-16-be" if charset == 4 else "latin-1"
        text = raw.decode(encoding, errors="replace").strip("\x00 \t\r\n")
        return text or None

    # --------------------------------------------------------------------- API

    def read(self, ip: str, obj_type: str | int, instance: int, prop: str = "present-value"):
        """Read one property. Returns the decoded value, or None on timeout/error."""
        ipaddress.ip_address(ip)
        type_num = OBJECT_TYPES[obj_type] if isinstance(obj_type, str) else obj_type
        packet = self.build_read_property(type_num, instance, PROPERTIES[prop])
        data = self._request(ip, packet, self._invoke_id)
        if data is None:
            return None
        if prop in ("object-name", "description"):
            return self.decode_text(data)
        kind, value = self.decode_value(data)
        if prop == "units" and value is not None:
            return UNITS.get(value, f"unit:{value}")
        if kind == "enum" and type_num in (3, 4, 5):    # binary objects
            return bool(value)
        return value

    def _request(self, ip: str, packet: bytes, invoke_id: int) -> bytes | None:
        """Send one confirmed request and return the reply that answers *it*.

        Datagrams from other hosts or with another invoke id (e.g. a late reply to a
        previous, timed-out request) are discarded instead of being mistaken for the answer.
        """
        deadline = time.monotonic() + self.timeout
        try:
            self.sock.sendto(packet, (ip, self.port))
            while True:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    return None
                self.sock.settimeout(remaining)
                data, (src, _) = self.sock.recvfrom(1500)
                a = self._apdu_offset(data)
                if src == ip and a is not None and len(data) > a + 1 and data[a + 1] == invoke_id:
                    return data
        except OSError:
            return None

    def is_alive(self, ip: str, device_instance: int) -> bool:
        """True if the device answers a ReadProperty on its own Device object."""
        return self.read(ip, "device", device_instance, "object-name") is not None

    def who_is(self, broadcast: str = "255.255.255.255", wait: float = 2.0) -> list[tuple[str, int]]:
        """Broadcast Who-Is and collect (ip, device_instance) from I-Am replies."""
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        self.sock.sendto(self.build_who_is(), (broadcast, self.port))
        found, old = [], self.sock.gettimeout()
        self.sock.settimeout(wait)
        try:
            while True:
                data, (src, _) = self.sock.recvfrom(1500)
                idx = data.find(b"\xC4")                # application tag 12 (object-id), len 4
                if idx != -1 and len(data) >= idx + 5:
                    oid = struct.unpack(">I", data[idx + 1:idx + 5])[0]
                    if oid >> 22 == OBJECT_TYPES["device"]:
                        found.append((src, oid & 0x3FFFFF))
        except OSError:
            pass
        finally:
            self.sock.settimeout(old)
        return found
