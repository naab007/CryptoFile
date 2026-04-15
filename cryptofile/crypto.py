"""CryptoFile on-disk format + streaming AES-256-GCM with Argon2id key derivation.

Design rationale
================

* **KDF: Argon2id** — memory-hard (resistant to GPU / ASIC cracking) and the current
  PHC recommendation. Parameters are stored in the file header so we can raise the
  cost ceiling later without breaking old files.

* **Cipher: AES-256-GCM** — hardware-accelerated (AES-NI) on any modern x86_64 CPU;
  authenticated by design. GCM is only unsafe when you reuse a (key, nonce) pair,
  which our counter-based nonce scheme makes impossible within a single file.

* **Streaming** — files are encrypted in 1 MiB chunks. Per-chunk authentication means
  a disk bit-flip or truncation is caught at the chunk boundary rather than only at
  end-of-file. Each chunk's tag is bound by AAD to: the full header, the chunk index,
  and a "final" flag — so neither chunk swapping nor truncation nor header tampering
  goes undetected.

* **Nonce construction** — 12 bytes = 8-byte random prefix (per file) || 4-byte
  big-endian chunk counter. Counter can't overflow practically (2^32 × 1 MiB = 4 PiB
  per file). Two encryptions of the same file with the same password will have
  different prefixes because we generate fresh salt + prefix every time.

File layout
-----------

::

    offset  size  field
    0       4     "CFIL"               magic
    4       1     version = 0x01
    5       1     kdf_algo = 0x01      (Argon2id)
    6       1     cipher_algo = 0x01   (AES-256-GCM, 1 MiB chunks)
    7       1     flags                reserved, must be 0
    8       4     memory_kib           u32 little-endian Argon2 memory cost (KiB)
    12      4     time_cost            u32 iterations
    16      1     parallelism          u8 lanes
    17      3     reserved             must be 0
    20      16    salt                 random
    36      8     base_nonce           random (prefix; chunk counter appended)
    44      8     plaintext_size       u64 for progress + integrity
    52      ...   chunk stream:
                    repeats N times:
                      ct   [chunk_size]    (last chunk may be shorter)
                      tag  [16]            GCM tag

    AAD per chunk = header_bytes[0:52] || chunk_index (u32 BE) || is_final (u8)
"""
from __future__ import annotations

import os
import secrets
import struct
from dataclasses import dataclass
from typing import Callable, Iterator

from argon2.low_level import Type as Argon2Type
from argon2.low_level import hash_secret_raw
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# ── Format constants ───────────────────────────────────────────────────────

MAGIC = b"CFIL"
FILE_VERSION = 0x01
KDF_ARGON2ID = 0x01
CIPHER_AESGCM_1MIB = 0x01

HEADER_SIZE = 52
CHUNK_SIZE = 1024 * 1024  # 1 MiB plaintext per chunk
GCM_TAG_SIZE = 16
GCM_NONCE_SIZE = 12
SALT_SIZE = 16
NONCE_PREFIX_SIZE = 8

# ── Default Argon2id parameters ────────────────────────────────────────────
# These are on the higher end of OWASP 2025 recommendations. Tuned to take ~1
# second on a 2020-era laptop. Stored per-file so future tightening is safe.
ARGON2_MEMORY_KIB = 256 * 1024   # 256 MiB
ARGON2_TIME_COST = 3             # iterations
ARGON2_PARALLELISM = 4           # lanes
KEY_SIZE = 32                    # AES-256


# ── Exceptions ─────────────────────────────────────────────────────────────


class CryptoError(Exception):
    """Base class for any error this module surfaces."""


class BadPassword(CryptoError):
    """Password did not produce a key that authenticates the file header.

    In practice this is also what you see if the file was corrupted — GCM
    can't distinguish between the two. We show a single "wrong password or
    corrupted file" message in the UI.
    """


class BadFormat(CryptoError):
    """Magic bytes or version number didn't match; file isn't CryptoFile output."""


class Cancelled(CryptoError):
    """Operation was cancelled via the ``cancel_check`` callback mid-stream.

    Callers catch this separately from real crypto errors so cancellation
    doesn't render as a scary "cryptographic error" messagebox.
    """


# ── Header ─────────────────────────────────────────────────────────────────


@dataclass(frozen=True)
class Header:
    memory_kib: int
    time_cost: int
    parallelism: int
    salt: bytes
    base_nonce: bytes
    plaintext_size: int

    def to_bytes(self) -> bytes:
        if len(self.salt) != SALT_SIZE:
            raise ValueError("salt must be 16 bytes")
        if len(self.base_nonce) != NONCE_PREFIX_SIZE:
            raise ValueError("base_nonce must be 8 bytes")
        return (
            MAGIC
            + bytes([FILE_VERSION, KDF_ARGON2ID, CIPHER_AESGCM_1MIB, 0])
            + struct.pack("<II", self.memory_kib, self.time_cost)
            + bytes([self.parallelism, 0, 0, 0])
            + self.salt
            + self.base_nonce
            + struct.pack("<Q", self.plaintext_size)
        )

    @classmethod
    def from_bytes(cls, data: bytes) -> "Header":
        if len(data) != HEADER_SIZE:
            raise BadFormat(f"header must be {HEADER_SIZE} bytes, got {len(data)}")
        if data[0:4] != MAGIC:
            raise BadFormat("bad magic — not a CryptoFile")
        version = data[4]
        if version != FILE_VERSION:
            raise BadFormat(f"unsupported file version: {version}")
        if data[5] != KDF_ARGON2ID:
            raise BadFormat(f"unsupported KDF algo: {data[5]}")
        if data[6] != CIPHER_AESGCM_1MIB:
            raise BadFormat(f"unsupported cipher algo: {data[6]}")
        # flags byte = data[7], reserved = 0 — don't hard-fail on unknown flags
        # yet, in case we add optional features later.
        memory_kib, time_cost = struct.unpack_from("<II", data, 8)
        parallelism = data[16]
        salt = data[20:36]
        base_nonce = data[36:44]
        (plaintext_size,) = struct.unpack_from("<Q", data, 44)
        return cls(
            memory_kib=memory_kib,
            time_cost=time_cost,
            parallelism=parallelism,
            salt=salt,
            base_nonce=base_nonce,
            plaintext_size=plaintext_size,
        )


# ── KDF ────────────────────────────────────────────────────────────────────


def derive_key(password: str, header: Header) -> bytes:
    """Argon2id(password, salt) → 32-byte AES key.

    Parameters come from the header, so each file uses its own KDF cost.
    """
    if not isinstance(password, str):
        raise TypeError("password must be a string")
    return hash_secret_raw(
        secret=password.encode("utf-8"),
        salt=header.salt,
        time_cost=header.time_cost,
        memory_cost=header.memory_kib,
        parallelism=header.parallelism,
        hash_len=KEY_SIZE,
        type=Argon2Type.ID,
    )


# ── Nonce + AAD helpers ────────────────────────────────────────────────────


def _chunk_nonce(base_nonce: bytes, chunk_index: int) -> bytes:
    """12-byte GCM nonce = 8-byte prefix || 4-byte big-endian counter."""
    return base_nonce + chunk_index.to_bytes(4, "big")


def _chunk_aad(header_bytes: bytes, chunk_index: int, is_final: bool) -> bytes:
    """AAD binds the full header, the chunk index, and the is-final flag.

    This defeats:
      * chunk-swapping attacks (each index is authenticated)
      * truncation (the last chunk carries a final-flag byte of 1)
      * header tampering (any header bit-flip breaks every chunk's tag)
    """
    return header_bytes + chunk_index.to_bytes(4, "big") + bytes([1 if is_final else 0])


# ── Progress / cancel callback types ──────────────────────────────────────


ProgressCallback = Callable[[int, int], None]  # (bytes_done, bytes_total) → None
# Cancel check: return True if the caller wants the stream to abort. Called
# once per chunk boundary, so worst-case latency is "one chunk's I/O + AEAD".
CancelCheck = Callable[[], bool]


# ── Encrypt ────────────────────────────────────────────────────────────────


def encrypt_stream(
    plain_in,
    enc_out,
    password: str,
    plaintext_size: int,
    progress: ProgressCallback | None = None,
    cancel_check: CancelCheck | None = None,
    *,
    memory_kib: int = ARGON2_MEMORY_KIB,
    time_cost: int = ARGON2_TIME_COST,
    parallelism: int = ARGON2_PARALLELISM,
) -> None:
    """Encrypt from ``plain_in`` to ``enc_out``, both binary file-like objects.

    ``plaintext_size`` must equal the exact number of bytes ``plain_in`` will
    produce — we write it into the header for integrity + progress.
    """
    if plaintext_size < 0:
        raise ValueError("plaintext_size must be >= 0")

    header = Header(
        memory_kib=memory_kib,
        time_cost=time_cost,
        parallelism=parallelism,
        salt=secrets.token_bytes(SALT_SIZE),
        base_nonce=secrets.token_bytes(NONCE_PREFIX_SIZE),
        plaintext_size=plaintext_size,
    )
    header_bytes = header.to_bytes()
    key = derive_key(password, header)
    aead = AESGCM(key)

    enc_out.write(header_bytes)
    if progress is not None:
        progress(0, plaintext_size)

    bytes_done = 0
    chunk_index = 0
    # We need to know which chunk is the LAST so we can set the is_final flag.
    # Easiest way without buffering the whole file: peek-ahead using a
    # double-buffer. Read chunk N; if the next read is empty, N is final.
    buffered = plain_in.read(CHUNK_SIZE)
    while buffered:
        if cancel_check is not None and cancel_check():
            raise Cancelled("encrypt cancelled")
        next_buf = plain_in.read(CHUNK_SIZE) if bytes_done + len(buffered) < plaintext_size else b""
        is_final = not next_buf
        nonce = _chunk_nonce(header.base_nonce, chunk_index)
        aad = _chunk_aad(header_bytes, chunk_index, is_final)
        ct = aead.encrypt(nonce, buffered, aad)
        enc_out.write(ct)
        bytes_done += len(buffered)
        chunk_index += 1
        if progress is not None:
            progress(bytes_done, plaintext_size)
        buffered = next_buf
        if is_final:
            break

    # Zero-byte input: still need one (empty) final chunk so the file can be
    # round-tripped and the is_final flag is authenticated.
    if plaintext_size == 0:
        nonce = _chunk_nonce(header.base_nonce, 0)
        aad = _chunk_aad(header_bytes, 0, True)
        ct = aead.encrypt(nonce, b"", aad)
        enc_out.write(ct)

    if bytes_done != plaintext_size:
        raise CryptoError(
            f"plaintext_size mismatch: declared {plaintext_size}, got {bytes_done}"
        )

    # C1 guard: the source must not have grown between stat() and the final
    # chunk. If it did, we would have silently truncated to `plaintext_size`
    # — then secure-deleted the larger source. Read one more byte; any data
    # there means the source grew during encryption and the output is
    # missing the tail. Abort before os.replace so the .partial is cleaned up.
    extra = plain_in.read(1)
    if extra:
        raise CryptoError(
            "source file grew during encryption — aborting before the "
            "truncated ciphertext can replace the source"
        )


# ── Decrypt ────────────────────────────────────────────────────────────────


def decrypt_stream(
    enc_in,
    plain_out,
    password: str,
    progress: ProgressCallback | None = None,
    cancel_check: CancelCheck | None = None,
) -> Header:
    """Decrypt from ``enc_in`` to ``plain_out``. Returns the parsed header.

    Raises :class:`BadFormat` if the file isn't CryptoFile output, or
    :class:`BadPassword` if the password doesn't authenticate the first
    chunk (which is the same symptom as a corrupted file).
    """
    header_bytes = enc_in.read(HEADER_SIZE)
    if len(header_bytes) < HEADER_SIZE:
        raise BadFormat("file too short to contain a header")
    header = Header.from_bytes(header_bytes)
    key = derive_key(password, header)
    aead = AESGCM(key)

    if progress is not None:
        progress(0, header.plaintext_size)

    remaining = header.plaintext_size
    chunk_index = 0
    seen_final = False
    while remaining > 0 or chunk_index == 0:
        if cancel_check is not None and cancel_check():
            raise Cancelled("decrypt cancelled")
        expected_pt_size = min(CHUNK_SIZE, remaining)
        is_final = expected_pt_size >= remaining  # last chunk when it finishes the file
        ct_size = expected_pt_size + GCM_TAG_SIZE
        ct = enc_in.read(ct_size)
        if len(ct) != ct_size:
            raise CryptoError(
                f"truncated ciphertext at chunk {chunk_index}: "
                f"expected {ct_size} bytes, got {len(ct)}"
            )
        nonce = _chunk_nonce(header.base_nonce, chunk_index)
        aad = _chunk_aad(header_bytes, chunk_index, is_final)
        try:
            pt = aead.decrypt(nonce, ct, aad)
        except Exception as e:
            # cryptography raises InvalidTag — convert so callers don't have
            # to import from the library directly.
            if chunk_index == 0:
                raise BadPassword("wrong password or corrupted file") from e
            raise CryptoError(
                f"chunk {chunk_index} failed authentication — file tampered or truncated"
            ) from e
        plain_out.write(pt)
        remaining -= len(pt)
        chunk_index += 1
        if progress is not None:
            progress(header.plaintext_size - remaining, header.plaintext_size)
        if is_final:
            seen_final = True
            break

    if not seen_final:
        raise CryptoError("encrypted file did not contain a final chunk")

    if enc_in.read(1):
        raise CryptoError("trailing bytes after final chunk — file tampered")

    return header
