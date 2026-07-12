from __future__ import annotations

_DECODE_CANDIDATES = ("utf-8-sig", "utf-8", "cp1251", "latin-1")


def decode_network_text(data: bytes | bytearray | memoryview | str | None) -> str:
    """Decode banner/payload bytes without corrupting non-English text.

    Most modern services send UTF-8, some older Windows/Russian services send
    cp1251, and latin-1 is kept as a lossless last resort for arbitrary bytes.
    """
    if data is None:
        return ""
    if isinstance(data, str):
        return data
    raw = bytes(data)
    if not raw:
        return ""
    for encoding in _DECODE_CANDIDATES:
        try:
            return raw.decode(encoding)
        except UnicodeDecodeError:
            continue
    return raw.decode("utf-8", "replace")


def encode_network_text(value: str | None, *, newline: bool = False) -> bytes:
    text = "" if value is None else str(value)
    if newline:
        text += "\r\n"
    return text.encode("utf-8", "replace")
