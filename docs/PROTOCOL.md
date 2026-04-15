# CryptoFile — On-disk format (v1)

This document is the authoritative spec for file-format **version `0x01`**
as shipped in CryptoFile 1.0.0. A valid CryptoFile-encrypted file consists
of a fixed-size header followed by a stream of authenticated ciphertext
chunks. Every field is stored in the byte order indicated below.

Design priorities in order: (1) authenticated encryption with no silent
modes of failure, (2) streaming — no whole-file buffering — (3) future
migrability via explicit version + algorithm identifiers.

## File layout

```
  offset  size  field
  ──────  ────  ──────────────────────────────────────────────────────
  0       4     magic = "CFIL"
  4       1     version = 0x01
  5       1     kdf_algo = 0x01       (Argon2id)
  6       1     cipher_algo = 0x01    (AES-256-GCM, 1 MiB chunks)
  7       1     flags                 reserved, must be 0
  8       4     memory_kib            u32 little-endian  (Argon2 m)
  12      4     time_cost             u32 little-endian  (Argon2 t)
  16      1     parallelism           u8                 (Argon2 p)
  17      3     reserved              must be 0
  20      16    salt                  random
  36      8     base_nonce            random (nonce prefix)
  44      8     plaintext_size        u64 little-endian
  52      …     chunk stream:
                  repeats N times:
                    ciphertext_bytes[chunk_pt_size]
                    gcm_tag[16]
                  last chunk may be shorter than CHUNK_SIZE.
```

**CHUNK_SIZE** is fixed at **1 MiB = 1,048,576 bytes** plaintext per chunk
for `cipher_algo = 0x01`. The last chunk's plaintext length is
`plaintext_size mod CHUNK_SIZE`, or `CHUNK_SIZE` if that modulus is zero
and the file is non-empty. A zero-byte plaintext still produces one
zero-length chunk (so the authenticated final-flag is always present).

Total file size on disk:

```
52 + ceil(plaintext_size / CHUNK_SIZE) × 16 + plaintext_size
```

(one tag per chunk; if `plaintext_size` is zero we still have one empty
chunk with its tag, so the minimum on-disk size is 68 bytes).

## Cryptographic constructions

### KDF — Argon2id

```
key = Argon2id(
    password = UTF-8 bytes of the user's password,
    salt     = header.salt,
    t        = header.time_cost,
    m        = header.memory_kib,    # kibibytes
    p        = header.parallelism,
    tag_len  = 32 bytes,
)
```

Default cost parameters written by v1.0.0 (stored per-file so they can be
raised later without breaking old files):

| Parameter   | Value    | Reason                                                  |
|-------------|----------|---------------------------------------------------------|
| memory_kib  | 262144   | 256 MiB — on the higher end of OWASP 2025 recommendations |
| time_cost   | 3        | three iterations                                        |
| parallelism | 4        | four lanes                                              |

On a 2020-era laptop this takes ≈ 1 second. Rising memory cost dominates
the attack math — memory-hard KDFs punish GPU / ASIC cracking far more
than pure-CPU functions like PBKDF2.

### Cipher — AES-256-GCM

Key: the 32 bytes returned by Argon2id above.

Nonce per chunk (12 bytes):

```
nonce(i) = header.base_nonce (8 bytes) || uint32_be(i)
```

`i` is the zero-indexed chunk counter. Counter overflow is impossible
within a single file (2^32 × 1 MiB = 4 PiB; no plausible file reaches it).
Two encryptions of the same file with the same password are nonce-safe
because `base_nonce` is freshly randomised per encrypt.

### AAD per chunk

Every chunk's GCM tag is bound to the full header plus chunk-index plus
final-flag byte:

```
aad(i) = header_bytes[0:52] || uint32_be(i) || uint8(is_final)
```

Where `is_final` is `1` for the last chunk, `0` otherwise. This means:

- **Header tampering** (any bit flip in the 52-byte header) invalidates
  every chunk's tag. Decrypt fails on chunk 0 with `BadPassword`.
- **Chunk swapping** (reorder within one file) fails because each chunk
  is pinned to its expected index.
- **Chunk splicing** (take a chunk from file A and put it into file B) is
  defeated by the per-file `base_nonce` + per-file salt: even if two
  files happened to share a password, the KDF keys differ, and even if
  they shared a KDF key, the `base_nonce` prefix differs → nonces
  wouldn't match, GCM fails.
- **Truncation** of the final chunk is caught: the honest final chunk
  has `is_final = 1`; a truncated chunk mid-file has `is_final = 0`.
  After decrypting, we check that we actually observed `is_final = 1`,
  and we also confirm no trailing bytes follow the expected end.

## Wire protocol — encrypt

```
1.  salt         ← 16 random bytes
2.  base_nonce   ← 8 random bytes
3.  header_bytes ← serialize fixed-layout header (above)
4.  key          ← Argon2id(password, salt, …)
5.  write header_bytes to output
6.  for chunk i in 0 .. ceil(size/CHUNK_SIZE) - 1:
        pt        ← read next chunk_plaintext_size bytes from input
        is_final  ← (bytes remaining after this chunk == 0)
        nonce     ← base_nonce || u32_be(i)
        aad       ← header_bytes || u32_be(i) || u8(is_final)
        ct+tag    ← AESGCM(key).encrypt(nonce, pt, aad)
        write ct+tag to output
7.  if plaintext_size == 0:
        emit one empty final chunk (aad with is_final = 1) so the
        authenticated "yes, we ended cleanly" marker is present.
```

## Wire protocol — decrypt

```
1.  header_bytes ← read 52 bytes from input
2.  parse header_bytes, validate magic + version + algo bytes
3.  key          ← Argon2id(password, header.salt, …)
4.  remaining    ← header.plaintext_size
5.  for chunk i from 0 upward:
        expected_pt = min(CHUNK_SIZE, remaining)
        is_final    = (expected_pt == remaining)
        read expected_pt + 16 bytes from input
        nonce       = header.base_nonce || u32_be(i)
        aad         = header_bytes || u32_be(i) || u8(is_final)
        pt          = AESGCM(key).decrypt(nonce, ct_tag, aad)
            # InvalidTag here → on chunk 0: BadPassword
            #                 → on later chunk: CryptoError (tampered/truncated)
        write pt to output
        remaining -= len(pt)
        if is_final: break
6.  require: we broke out of the loop via is_final (otherwise truncated).
7.  require: no trailing bytes after the final chunk's tag.
```

### Decrypt error mapping

| What fails                                      | Exception raised      |
|-------------------------------------------------|-----------------------|
| Magic ≠ "CFIL"                                  | `BadFormat`           |
| Unknown `version` / `kdf_algo` / `cipher_algo`  | `BadFormat`           |
| Header shorter than 52 bytes                    | `BadFormat`           |
| Chunk 0 GCM tag fails                           | `BadPassword`         |
| Later chunk GCM tag fails                       | `CryptoError` ("chunk N failed authentication — file tampered or truncated") |
| Chunk read returned fewer bytes than expected   | `CryptoError` ("truncated ciphertext at chunk N") |
| Decrypt loop ran but never saw `is_final = 1`  | `CryptoError` ("encrypted file did not contain a final chunk") |
| Trailing bytes after the final chunk's tag      | `CryptoError` ("trailing bytes after final chunk — file tampered") |
| Wrong key for a password-protected file         | surfaces as `BadPassword` (symptom is the same as tampering on chunk 0) |

## Why these specific choices

- **Argon2id over PBKDF2-SHA256 / scrypt / bcrypt.** Argon2 is the PHC
  2015 winner and has been the RFC 9106 standard since 2021. Memory-hard,
  ASIC-hostile, tunable along all three axes. `argon2-cffi` is a
  well-maintained binding to the reference implementation.
- **AES-256-GCM over ChaCha20-Poly1305.** Both are valid AEADs. AES-GCM
  has hardware acceleration (AES-NI) on every x86_64 CPU since Westmere
  (2010); on the target audience's hardware it's 3-10× faster than
  ChaCha. The classic GCM pitfall (nonce reuse) is structurally
  impossible here — per-file fresh `base_nonce` + per-chunk counter.
- **1 MiB chunks.** Large enough that GCM/AES-NI throughput dominates
  overhead (the 16-byte tag is 0.0015 % of payload). Small enough that
  a corrupted file fails at the nearest chunk boundary rather than at
  end-of-file. Small enough that memory footprint stays negligible.
- **Nonce = random prefix ‖ counter**, not fully random per chunk, because
  a 96-bit random nonce has a collision probability that requires
  audit-grade thinking about dataset size; a counter guarantees
  non-collision by construction and keeps the prefix-randomness budget
  for across-file distinctness.
- **Plaintext size in the header** rather than derivable from
  ciphertext size — makes progress reporting trivial and lets decrypt
  detect truncated last-chunks without parsing a length prefix inside
  each chunk.

## Test vectors

The test suite in `tests/test_crypto.py` covers every field of the spec:

- Round-trips for sizes 0, 1, `CHUNK_SIZE-1`, `CHUNK_SIZE`, `CHUNK_SIZE+1`,
  and multi-chunk with a tail remainder.
- Header round-trip (serialize → parse → equal dataclass).
- Two encrypts of the same plaintext produce different salts, nonces,
  and ciphertexts (salt + base_nonce freshness).
- Bad magic → `BadFormat`.
- Tampered header byte → `BadPassword` on chunk 0.
- Tampered ciphertext byte → `BadPassword` (chunk 0 of whichever chunk
  holds it).
- Truncated ciphertext → `CryptoError("truncated ciphertext …")`.
- Trailing bytes after the final chunk → `CryptoError("trailing bytes …")`.
- Chunk swap between chunk 0 and chunk 1 → `BadPassword`
  (proves the AAD chunk-index binding works).
- Wrong password → `BadPassword`.
- Unicode password (pássw0rd-日本語-🔐) → roundtrips.
- Header stores the custom `memory_kib` / `time_cost` / `parallelism` the
  caller passed to `encrypt_stream`.

If you change the spec, every one of these must continue to pass on
existing files (back-compat) and pass on the new format bytes (forward).
