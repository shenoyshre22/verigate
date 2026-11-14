"""Unsafe reversible protector for synthetic test fixtures only; never use for real data."""


class TestProtector:
    def protect(self, data: bytes, context: bytes) -> bytes:
        return b"test-ciphertext:" + bytes(byte ^ 0x5A for byte in data)

    def unprotect(self, data: bytes, context: bytes) -> bytes:
        if not data.startswith(b"test-ciphertext:"):
            raise ValueError("invalid ciphertext")
        return bytes(byte ^ 0x5A for byte in data[len(b"test-ciphertext:"):])
