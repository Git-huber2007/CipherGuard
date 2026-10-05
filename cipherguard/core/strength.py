"""Quantified security strength.

Findings that say "weak" are not actionable at fleet scale. An agency with four
hundred gateways needs an ordering: which link do we fix first, and why that one.
That requires putting a number on each negotiated suite.

Two numbers, because there are two adversaries:

  classical_bits  work factor for a conventional attacker, in bits
  quantum_bits    work factor once a cryptanalytically relevant quantum
                  computer exists

Grover's algorithm halves the effective key length of a symmetric cipher, so
AES-256 drops to 128 and AES-128 to 64. Shor's algorithm breaks finite-field and
elliptic-curve Diffie-Hellman outright, so every classical key exchange in use
today has a quantum strength of zero regardless of modulus size. That asymmetry
is the whole reason the post-quantum migration is urgent for key establishment
long before it is urgent for bulk encryption, and expressing it numerically is
what turns "enable PQC eventually" into a ranked work queue.

Figures follow NIST SP 800-57 Part 1 Rev. 5 Table 2 for classical strength.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from . import constants as C

# --------------------------------------------------------------------------
# Symmetric encryption
# --------------------------------------------------------------------------

# name -> (classical bits, block size in bits)
ENCR_STRENGTH: dict[str, tuple[int, int]] = {
    "ENCR_DES": (56, 64),
    "ENCR_DES_IV64": (56, 64),
    "ENCR_DES_IV32": (56, 64),
    "ENCR_3DES": (112, 64),          # meet-in-the-middle caps 168-bit keying at 112
    "ENCR_IDEA": (128, 64),
    "ENCR_CAST": (128, 64),
    "ENCR_BLOWFISH": (128, 64),
    "ENCR_3IDEA": (112, 64),
    "ENCR_RC5": (128, 64),
    "ENCR_NULL": (0, 0),
    "ENCR_AES_CBC": (128, 128),      # refined by the negotiated key length
    "ENCR_AES_CTR": (128, 128),
    "ENCR_AES_CCM_8": (128, 128),
    "ENCR_AES_CCM_12": (128, 128),
    "ENCR_AES_CCM_16": (128, 128),
    "ENCR_AES_GCM_8": (128, 128),
    "ENCR_AES_GCM_12": (128, 128),
    "ENCR_AES_GCM_16": (128, 128),
    "ENCR_CHACHA20_POLY1305": (256, 512),
    "ENCR_CAMELLIA_CBC": (128, 128),
    "ENCR_CAMELLIA_CTR": (128, 128),
    "ENCR_NULL_AUTH_AES_GMAC": (0, 128),
    # IKEv1 spellings
    "DES_CBC": (56, 64),
    "3DES_CBC": (112, 64),
    "AES_CBC": (128, 128),
    "IDEA_CBC": (128, 64),
    "BLOWFISH_CBC": (128, 64),
    "CAST_CBC": (128, 64),
    "CAMELLIA_CBC": (128, 128),
}

# --------------------------------------------------------------------------
# Integrity
# --------------------------------------------------------------------------

INTEG_STRENGTH: dict[str, int] = {
    "AUTH_NONE": 0,
    "AUTH_HMAC_MD5_96": 64,      # HMAC survives MD5 collisions, but only just
    "AUTH_HMAC_MD5_128": 64,
    "AUTH_KPDK_MD5": 64,
    "AUTH_DES_MAC": 56,
    "AUTH_HMAC_SHA1_96": 96,
    "AUTH_HMAC_SHA1_160": 96,
    "AUTH_AES_XCBC_96": 96,
    "AUTH_AES_CMAC_96": 96,
    "AUTH_HMAC_SHA2_256_128": 128,
    "AUTH_HMAC_SHA2_384_192": 192,
    "AUTH_HMAC_SHA2_512_256": 256,
    "AUTH_AES_128_GMAC": 128,
    "AUTH_AES_192_GMAC": 192,
    "AUTH_AES_256_GMAC": 256,
    "AUTH_HMAC_MD5": 64,
    "AUTH_HMAC_SHA1": 96,
    "AUTH_HMAC_SHA2_256": 128,
}

PRF_STRENGTH: dict[str, int] = {
    "PRF_HMAC_MD5": 64,
    "PRF_HMAC_SHA1": 96,
    "PRF_HMAC_TIGER": 96,
    "PRF_AES128_XCBC": 128,
    "PRF_AES128_CMAC": 128,
    "PRF_HMAC_SHA2_256": 128,
    "PRF_HMAC_SHA2_384": 192,
    "PRF_HMAC_SHA2_512": 256,
}

# --------------------------------------------------------------------------
# Key establishment
#
# quantum_bits is zero for every classical group: Shor solves both the discrete
# logarithm and the elliptic-curve discrete logarithm in polynomial time, so a
# larger modulus buys nothing at all against that adversary.
# --------------------------------------------------------------------------

# group id -> (classical bits, quantum bits, family)
DH_STRENGTH: dict[int, tuple[int, int, str]] = {
    0: (0, 0, "none"),
    1: (32, 0, "modp"),       # 768-bit: broken in practice
    2: (80, 0, "modp"),       # 1024-bit: within nation-state precomputation
    5: (96, 0, "modp"),       # 1536-bit
    14: (112, 0, "modp"),     # 2048-bit
    15: (128, 0, "modp"),     # 3072-bit
    16: (152, 0, "modp"),     # 4096-bit
    17: (176, 0, "modp"),
    18: (200, 0, "modp"),
    19: (128, 0, "ecp"),      # NIST P-256
    20: (192, 0, "ecp"),      # NIST P-384
    21: (256, 0, "ecp"),      # NIST P-521
    22: (80, 0, "modp"),
    23: (112, 0, "modp"),
    24: (112, 0, "modp"),
    25: (96, 0, "ecp"),
    26: (112, 0, "ecp"),
    27: (112, 0, "ecp"),
    28: (128, 0, "ecp"),
    29: (192, 0, "ecp"),
    30: (256, 0, "ecp"),
    31: (128, 0, "ecp"),      # Curve25519
    32: (224, 0, "ecp"),      # Curve448
    35: (128, 128, "ml-kem"), # ML-KEM-512,  NIST PQC category 1
    36: (192, 192, "ml-kem"), # ML-KEM-768,  category 3
    37: (256, 256, "ml-kem"), # ML-KEM-1024, category 5
}


@dataclass
class SuiteStrength:
    """The security level of a negotiated association, weakest-link scored."""

    classical_bits: int
    quantum_bits: int
    block_bits: int
    kex_family: str
    detail: dict[str, int]
    # Key establishment on its own, before the cipher's Grover margin caps the
    # association's quantum_bits. Lets a caller tell "the key exchange is
    # classical" from "the key exchange is post-quantum and the cipher is short".
    kex_quantum_bits: int = 0
    # One entry per key exchange that contributes: the type 4 method, then any
    # RFC 9370 additional key exchange that is not NONE.
    kex_components: list[dict] = field(default_factory=list)

    @property
    def hybrid(self) -> bool:
        return len(self.kex_components) > 1

    @property
    def classical_grade(self) -> str:
        b = self.classical_bits
        if b >= 192:
            return "excellent"
        if b >= 128:
            return "adequate"
        if b >= 112:
            return "minimum"
        if b >= 80:
            return "deprecated"
        return "broken"

    @property
    def quantum_safe(self) -> bool:
        return self.quantum_bits >= 128

    def to_dict(self) -> dict:
        return {
            "classical_bits": self.classical_bits,
            "quantum_bits": self.quantum_bits,
            "block_bits": self.block_bits,
            "kex_family": self.kex_family,
            "classical_grade": self.classical_grade,
            "quantum_safe": self.quantum_safe,
            "components": self.detail,
            "kex_quantum_bits": self.kex_quantum_bits,
            "hybrid": self.hybrid,
            "kex_components": self.kex_components,
        }


def _encr_bits(name: str, key_length: int | None) -> tuple[int, int]:
    bits, block = ENCR_STRENGTH.get(name, (128, 128))
    if key_length and name.startswith(("ENCR_AES", "AES")):
        bits = key_length
    return bits, block


def _key_exchange(transforms) -> tuple[int | None, int | None, str, list[dict]]:
    """Combined strength of the key exchange, hybrid or not.

    RFC 9370 mixes the shared secret of every key exchange into the keys in
    turn, so an attacker has to break all of them to recover a session key. The
    combination is therefore as strong as its strongest component, against each
    adversary separately: Curve25519 with ML-KEM-768 takes ML-KEM's 192 bits
    against a quantum attacker, where Curve25519 alone gives none. Two
    classical groups still give none, because Shor breaks both.

    Within one transform type the usual rule holds. Several alternatives of the
    same type only appear in an initiator's offer, any of them may be chosen,
    and the slot is scored at the weakest. An additional key exchange that
    offers NONE as an alternative therefore contributes nothing until a
    responder is seen to select the real one.
    """
    slots: dict[int, list[tuple[int, int, str, int, str]]] = {}
    for t in transforms:
        if t.type_id not in C.KE_TRANSFORM_TYPES:
            continue
        # An unrecognised group gets the benefit of the doubt as the main key
        # exchange, as before, but earns no credit as an additional one.
        unknown = (112, 0, "modp") if t.type_id == C.TRANSFORM_KE else (0, 0, "unknown")
        c, q, fam = DH_STRENGTH.get(t.value_id, unknown)
        slots.setdefault(t.type_id, []).append((c, q, fam, t.value_id, t.name))

    if not slots:
        return None, None, "none", []

    components: list[dict] = []
    for type_id in sorted(slots):
        alts = slots[type_id]
        c = min(a[0] for a in alts)
        q = min(a[1] for a in alts)
        weakest = min(alts, key=lambda a: (a[1], a[0]))
        if type_id != C.TRANSFORM_KE and weakest[2] in ("none", "unknown"):
            continue  # this additional slot may be, or is, unused
        components.append({
            "slot": C.TRANSFORM_TYPE.get(type_id, f"TYPE_{type_id}"),
            "group": weakest[3],
            "name": weakest[4],
            "family": weakest[2],
            "classical_bits": c,
            "quantum_bits": q,
        })

    if not components:
        return None, None, "none", []
    families: list[str] = []
    for comp in components:
        if comp["family"] not in families:
            families.append(comp["family"])
    return (
        max(comp["classical_bits"] for comp in components),
        max(comp["quantum_bits"] for comp in components),
        "+".join(families),
        components,
    )


def score_proposal(transforms) -> SuiteStrength:
    """Score a proposal at its weakest component.

    A chain is only as strong as its weakest link, and mixed suites are common
    in the field: AES-256 paired with SHA-1 and DH Group 2 is not a 256-bit
    association, it is an 80-bit one. Averaging would flatter it badly.

    The key exchange is one link in that chain. When it is a hybrid of several
    exchanges, that link is scored by `_key_exchange`, and the rest of the
    chain is still bounded by its weakest member.
    """
    transforms = list(transforms)
    encr_bits = block_bits = None
    integ_bits = prf_bits = None

    for t in transforms:
        if t.type_id == 1:
            bits, block = _encr_bits(t.name, t.key_length)
            encr_bits = bits if encr_bits is None else min(encr_bits, bits)
            block_bits = block if block_bits is None else min(block_bits, block)
        elif t.type_id == 2:
            v = PRF_STRENGTH.get(t.name, 128)
            prf_bits = v if prf_bits is None else min(prf_bits, v)
        elif t.type_id == 3:
            v = INTEG_STRENGTH.get(t.name, 128)
            integ_bits = v if integ_bits is None else min(integ_bits, v)

    dh_c, dh_q, family, kex_components = _key_exchange(transforms)

    components = {
        k: v
        for k, v in {
            "encryption": encr_bits,
            "prf": prf_bits,
            "integrity": integ_bits,
            "key_exchange": dh_c,
        }.items()
        if v is not None
    }
    if not components:
        return SuiteStrength(0, 0, 0, "unknown", {})

    classical = min(components.values())
    # Quantum strength is bounded by the key exchange: if the session key can be
    # recovered, the cipher's own Grover margin is irrelevant.
    grover = (encr_bits or 0) // 2
    quantum = min(grover, dh_q if dh_q is not None else 0)

    return SuiteStrength(
        classical_bits=classical,
        quantum_bits=quantum,
        block_bits=block_bits or 0,
        kex_family=family,
        detail=components,
        kex_quantum_bits=dh_q or 0,
        kex_components=kex_components,
    )


# --------------------------------------------------------------------------
# Sweet32: concrete birthday bound for 64-bit block ciphers
# --------------------------------------------------------------------------

SWEET32_PRACTICAL_BLOCKS = 2**32  # collisions become exploitable around here


def sweet32_exposure(block_bits: int, bytes_observed: int, seconds_observed: float,
                     rekey_seconds: int) -> dict | None:
    """Quantify Sweet32 risk from observed throughput instead of asserting it.

    For a cipher with a b-bit block, distinct ciphertext blocks start colliding
    around 2^(b/2) by the birthday bound. At 64 bits that is 2^32 blocks, or
    roughly 32 GB of traffic under one key — a threshold a backbone tunnel
    crosses in minutes, not years. Whether a given SA actually reaches it
    depends on its throughput and how often it rekeys, both of which are
    directly observable, so the finding can carry a real number rather than a
    generic warning.
    """
    if block_bits == 0 or block_bits >= 128:
        return None

    block_bytes = block_bits // 8
    threshold_bytes = SWEET32_PRACTICAL_BLOCKS * block_bytes

    rate = bytes_observed / seconds_observed if seconds_observed > 0 else 0.0
    bytes_per_key = rate * rekey_seconds

    return {
        "block_bits": block_bits,
        "threshold_gb": round(threshold_bytes / 1e9, 1),
        "observed_rate_mbps": round(rate * 8 / 1e6, 2),
        "bytes_per_rekey_gb": round(bytes_per_key / 1e9, 2),
        "ratio_to_threshold": round(bytes_per_key / threshold_bytes, 3)
        if threshold_bytes
        else 0.0,
        "seconds_to_threshold": round(threshold_bytes / rate, 1) if rate > 0 else None,
        "exceeds": bytes_per_key >= threshold_bytes,
    }
