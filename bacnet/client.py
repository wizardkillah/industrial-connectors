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
# Subset of BACnetEngineeringUnits (ASHRAE 135, clause 21).
UNITS = {
    0: "m2", 4: "V", 5: "A", 29: "Pa", 30: "kPa", 33: "bar", 47: "kWh",
    48: "kW", 53: "mbar", 55: "ppm", 62: "%", 64: "degC", 85: "m3/h",
    95: "", 96: "l/min", 133: "L/s",
}


class BacnetError(Exception):
    pass


class BacnetClient:
    """One UDP socket per instance. Not thread-safe: use one client per thread."""

    def __init__(self, local_ip: str | None = None, timeout: float = 1.0, port: int = BACNET_PORT):
        self.port = port
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
    def decode_value(data: bytes):
        """Return (kind, value) from a ComplexACK, or (None, None)."""
        if not data or len(data) < 8 or (data[6] & 0xF0) != 0x30:
            return None, None
        for i in range(6, len(data) - 2):
            if data[i] != 0x3E:                         # opening tag 3 = property value
                continue
            tag = data[i + 1]
            number, length = (tag >> 4) & 0xF, tag & 0x7
            start = i + 2
            if length == 5 and i + 2 < len(data):       # extended length
                length, start = data[i + 2], i + 3
            if number == 4 and length == 4 and len(data) >= start + 4:
                return "float", round(struct.unpack(">f", data[start:start + 4])[0], 3)
            if number == 9 and length == 1 and len(data) >= start + 1:
                return "enum", data[start]
            if number == 2 and 0 < length <= 4 and len(data) >= start + length:
                return "uint", int.from_bytes(data[start:start + length], "big")
            if number == 1 and len(data) >= start + 1:
                return "bool", bool(data[start])
            break
        return None, None

    @staticmethod
    def decode_text(data: bytes) -> str | None:
        if not data or len(data) < 8 or (data[6] & 0xF0) != 0x30:
            return None
        for i in range(6, len(data) - 3):
            if data[i] != 0x3E:
                continue
            j = i + 1
            length = data[j] & 0x7
            if length == 5 and j + 1 < len(data):
                length, start = data[j + 1], j + 2
            else:
                start = j + 1
            if start >= len(data):
                break
            charset = data[start]
            raw = data[start + 1:start + length]
            encoding = "utf-8" if charset == 0 else "utf-16-be" if charset == 4 else "latin-1"
            text = raw.decode(encoding, errors="replace").strip("\x00 \t\r\n")
            return text or None
        return None

    # --------------------------------------------------------------------- API

    def read(self, ip: str, obj_type: str | int, instance: int, prop: str = "present-value"):
        """Read one property. Returns the decoded value, or None on timeout/error."""
        ipaddress.ip_address(ip)
        type_num = OBJECT_TYPES[obj_type] if isinstance(obj_type, str) else obj_type
        packet = self.build_read_property(type_num, instance, PROPERTIES[prop])
        try:
            self.sock.sendto(packet, (ip, self.port))
            data, _ = self.sock.recvfrom(1500)
        except OSError:
            return None
        if prop in ("object-name", "description"):
            return self.decode_text(data)
        kind, value = self.decode_value(data)
        if prop == "units" and value is not None:
            return UNITS.get(value, f"unit:{value}")
        if kind == "enum" and type_num in (3, 4, 5):    # binary objects
            return bool(value)
        return value

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
