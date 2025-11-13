"""Minimal CBOR encoder for the harness."""
from __future__ import annotations

from typing import Any, Dict, Iterable


def _encode_uint(major: int, value: int) -> bytearray:
    buf = bytearray()
    if value < 24:
        buf.append((major << 5) | value)
    elif value < 256:
        buf.extend(((major << 5) | 24, value))
    elif value < 65536:
        buf.append((major << 5) | 25)
        buf.extend(value.to_bytes(2, "big"))
    elif value < 4294967296:
        buf.append((major << 5) | 26)
        buf.extend(value.to_bytes(4, "big"))
    else:
        buf.append((major << 5) | 27)
        buf.extend(value.to_bytes(8, "big"))
    return buf


def _encode_int(value: int) -> bytearray:
    if value >= 0:
        return _encode_uint(0, value)
    return _encode_uint(1, -1 - value)


def _encode_bytes(value: bytes) -> bytearray:
    buf = _encode_uint(2, len(value))
    buf.extend(value)
    return buf


def _encode_text(value: str) -> bytearray:
    data = value.encode("utf-8")
    buf = _encode_uint(3, len(data))
    buf.extend(data)
    return buf


def _encode_array(values: Iterable[Any]) -> bytearray:
    buf = _encode_uint(4, len(list(values)))
    for item in values:
        buf.extend(encode(item))
    return buf


def _encode_map(value: Dict[Any, Any]) -> bytearray:
    buf = _encode_uint(5, len(value))
    for key, item in value.items():
        buf.extend(encode(key))
        buf.extend(encode(item))
    return buf


def encode(value: Any) -> bytes:
    """Encode a subset of CBOR supporting int/str/bytes/list/dict."""
    if isinstance(value, int):
        return bytes(_encode_int(value))
    if isinstance(value, bytes):
        return bytes(_encode_bytes(value))
    if isinstance(value, str):
        return bytes(_encode_text(value))
    if isinstance(value, (list, tuple)):
        return bytes(_encode_array(value))
    if isinstance(value, dict):
        # maintain insertion order
        return bytes(_encode_map(value))
    raise TypeError(f"Unsupported CBOR type: {type(value)!r}")
