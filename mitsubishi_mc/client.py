"""Mitsubishi MELSEC MC protocol client, A-compatible 1E frame (binary), pure Python.

Targets FX3G / FX3GC / FX3U-class PLCs behind an Ethernet adapter
(FX3U-ENET, FX3U-ENET-ADP, FX3GE built-in port) that speak the 1E frame.

Frame layout (binary, little-endian)::

    request   subheader | PC no (0xFF) | timer(2) | head device(4) | device code(2) | points | 0x00 [| data]
    response  subheader|0x80 | end code [| abnormal code] | data

    subheader: 0x00 batch read bits | 0x01 batch read words | 0x02 batch write bits | 0x03 batch write words
    bit data : 2 points per byte, first point in the high nibble
    word data: 16-bit little-endian

On FX series X/Y device numbers are OCTAL (Y010 is point 8).  ``parse_device``
handles that.

Status: validated against the public 1E frame specification and a built-in PLC
simulator (see tests/).  Verify against your own hardware before relying on it.
"""
from __future__ import annotations

import re
import socket
import struct

SUB_READ_BITS, SUB_READ_WORDS, SUB_WRITE_BITS, SUB_WRITE_WORDS = 0x00, 0x01, 0x02, 0x03

BIT_DEVICES = {"X", "Y", "M", "S", "TS", "TC", "CS", "CC"}
WORD_DEVICES = {"D", "R", "TN", "CN"}
OCTAL_DEVICES = {"X", "Y"}

MAX_BITS = 256
MAX_WORDS = 256


class McError(Exception):
    def __init__(self, end_code: int, abnormal: int | None = None):
        self.end_code, self.abnormal = end_code, abnormal
        super().__init__(f"PLC end code 0x{end_code:02X}" +
                         (f", abnormal code 0x{abnormal:02X}" if abnormal is not None else ""))


def parse_device(text: str) -> tuple[str, int]:
    """'D104' -> ('D', 104);  'Y10' -> ('Y', 8)  (X/Y are octal)."""
    m = re.fullmatch(r"([A-Za-z]{1,2})(\d+)", text.strip())
    if not m:
        raise ValueError(f"Invalid device address: {text!r}")
    name, num = m.group(1).upper(), m.group(2)
    if name not in BIT_DEVICES | WORD_DEVICES:
        raise ValueError(f"Unsupported device: {name}")
    return name, int(num, 8) if name in OCTAL_DEVICES else int(num)


def _device_code(name: str) -> bytes:
    padded = name.ljust(2)                      # 'D' -> 'D ' (0x4420), sent low byte first
    return bytes([ord(padded[1]), ord(padded[0])])


class McClient:
    def __init__(self, host: str, port: int = 5007, timeout: float = 3.0, monitoring_timer: int = 0x10):
        self.host, self.port, self.timeout, self.timer = host, port, timeout, monitoring_timer
        self.sock: socket.socket | None = None

    # connection ------------------------------------------------------------
    def connect(self) -> "McClient":
        self.sock = socket.create_connection((self.host, self.port), timeout=self.timeout)
        return self

    def close(self) -> None:
        if self.sock:
            try:
                self.sock.close()
            finally:
                self.sock = None

    def __enter__(self):
        return self.connect()

    def __exit__(self, *exc):
        self.close()

    # framing ---------------------------------------------------------------
    def _header(self, sub: int, name: str, head: int, points: int) -> bytes:
        return (bytes([sub, 0xFF]) + struct.pack("<H", self.timer) +
                struct.pack("<I", head) + _device_code(name) + bytes([points & 0xFF, 0x00]))   # 256 points is sent as 0

    def _recv_exact(self, n: int) -> bytes:
        buf = b""
        while len(buf) < n:
            chunk = self.sock.recv(n - len(buf))
            if not chunk:
                raise ConnectionError("PLC closed the connection")
            buf += chunk
        return buf

    def _exchange(self, request: bytes, data_len: int) -> bytes:
        if not self.sock:
            raise ConnectionError("Not connected")
        self.sock.sendall(request)
        head = self._recv_exact(2)
        if head[1] != 0x00:
            # Only end code 0x5B (PLC error) is followed by an abnormal code byte.
            abnormal = self._recv_exact(1)[0] if head[1] == 0x5B else None
            raise McError(head[1], abnormal)
        return self._recv_exact(data_len)

    # reads -----------------------------------------------------------------
    def read_bits(self, device: str, count: int = 1) -> list[bool]:
        name, head = parse_device(device)
        if name not in BIT_DEVICES:
            raise ValueError(f"{name} is not a bit device")
        if not 1 <= count <= MAX_BITS:
            raise ValueError(f"count must be 1..{MAX_BITS}")
        data = self._exchange(self._header(SUB_READ_BITS, name, head, count), (count + 1) // 2)
        bits = []
        for i in range(count):
            byte = data[i // 2]
            bits.append(bool((byte >> 4) & 1 if i % 2 == 0 else byte & 1))
        return bits

    def read_words(self, device: str, count: int = 1, signed: bool = False) -> list[int]:
        name, head = parse_device(device)
        if name not in WORD_DEVICES:
            raise ValueError(f"{name} is not a word device")
        if not 1 <= count <= MAX_WORDS:
            raise ValueError(f"count must be 1..{MAX_WORDS}")
        data = self._exchange(self._header(SUB_READ_WORDS, name, head, count), count * 2)
        return list(struct.unpack(f"<{count}{'h' if signed else 'H'}", data))

    def read_float(self, device: str) -> float:
        """IEEE-754 float stored in two consecutive words (low word first, as DEMUL/FLT do)."""
        lo, hi = self.read_words(device, 2)
        return struct.unpack("<f", struct.pack("<HH", lo, hi))[0]

    # writes ----------------------------------------------------------------
    def write_bits(self, device: str, values: list[bool]) -> None:
        name, head = parse_device(device)
        if name not in BIT_DEVICES:
            raise ValueError(f"{name} is not a bit device")
        if not 1 <= len(values) <= MAX_BITS:
            raise ValueError(f"values must have 1..{MAX_BITS} items")
        packed = bytearray((len(values) + 1) // 2)
        for i, v in enumerate(values):
            packed[i // 2] |= (0x10 if v else 0) if i % 2 == 0 else (0x01 if v else 0)
        self._exchange(self._header(SUB_WRITE_BITS, name, head, len(values)) + bytes(packed), 0)

    def write_words(self, device: str, values: list[int]) -> None:
        name, head = parse_device(device)
        if name not in WORD_DEVICES:
            raise ValueError(f"{name} is not a word device")
        if not 1 <= len(values) <= MAX_WORDS:
            raise ValueError(f"values must have 1..{MAX_WORDS} items")
        payload = b"".join(struct.pack("<H", v & 0xFFFF) for v in values)
        self._exchange(self._header(SUB_WRITE_WORDS, name, head, len(values)) + payload, 0)
