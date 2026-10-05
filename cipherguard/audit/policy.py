"""Cryptographic policy baseline.

Encodes the deprecation positions of NIST SP 800-77 Rev. 1 (Guide to IPsec VPNs),
RFC 8247 (Algorithm Implementation Requirements for IKEv2) and NIST SP 800-131A
Rev. 2, plus the post-quantum migration targets of FIPS 203 / 204.

Everything the audit engine treats as "bad" is named here rather than scattered
through rule code, so a deploying agency can retarget the tool to its own
crypto directive by editing one file.
"""

from __future__ import annotations

# --------------------------------------------------------------------------
# Encryption transforms
# --------------------------------------------------------------------------

# Broken or withdrawn outright.
ENCR_PROHIBITED = {
    "ENCR_DES": "56-bit effective key, exhaustible; withdrawn by SP 800-131A Rev. 2",
    "ENCR_DES_IV64": "single DES variant, 56-bit effective key",
    "ENCR_DES_IV32": "single DES variant, 56-bit effective key",
    "ENCR_3DES": "64-bit block invites Sweet32 birthday collisions; MUST NOT per RFC 8247",
    "ENCR_RC5": "unanalysed for IKEv2 use, no current implementation requirement",
    "ENCR_IDEA": "64-bit block, obsolete",
    "ENCR_CAST": "64-bit block, obsolete",
    "ENCR_BLOWFISH": "64-bit block, obsolete",
    "ENCR_3IDEA": "64-bit block, obsolete",
    "ENCR_NULL": "no confidentiality: payload traverses the link in plaintext",
    # IKEv1 spells its algorithms differently, and omitting these meant a real
    # IKEv1 gateway negotiating 3DES bypassed this rule entirely — found by
    # validating against a real Windows capture, never by synthetic traffic,
    # because the generator and the policy shared the same vocabulary.
    "DES_CBC": "56-bit effective key, exhaustible; withdrawn by SP 800-131A Rev. 2",
    "3DES_CBC": "64-bit block invites Sweet32 birthday collisions; MUST NOT per RFC 8247",
    "IDEA_CBC": "64-bit block, obsolete",
    "BLOWFISH_CBC": "64-bit block, obsolete",
    "CAST_CBC": "64-bit block, obsolete",
    "RC5_R16_B64_CBC": "64-bit block, unanalysed for IPsec use",
}

# Acceptable but not preferred.
ENCR_LEGACY = {
    "ENCR_AES_CBC": "CBC without AEAD; prefer AES-GCM (RFC 8247 recommends AEAD)",
    "ENCR_AES_CTR": "counter mode without integrated authentication; prefer AES-GCM",
    "ENCR_CAMELLIA_CBC": "permitted but not a NIST-approved algorithm",
}

ENCR_PREFERRED = {
    "ENCR_AES_GCM_16",
    "ENCR_AES_GCM_12",
    "ENCR_CHACHA20_POLY1305",
    "ENCR_AES_CCM_16",
}

AEAD_TRANSFORMS = {
    "ENCR_AES_GCM_8",
    "ENCR_AES_GCM_12",
    "ENCR_AES_GCM_16",
    "ENCR_AES_CCM_8",
    "ENCR_AES_CCM_12",
    "ENCR_AES_CCM_16",
    "ENCR_CHACHA20_POLY1305",
    "ENCR_NULL_AUTH_AES_GMAC",
}

MIN_KEY_BITS = 128

# --------------------------------------------------------------------------
# Integrity and PRF
# --------------------------------------------------------------------------

INTEG_PROHIBITED = {
    "AUTH_HMAC_MD5_96": "MD5 is collision-broken; MUST NOT per RFC 8247",
    "AUTH_HMAC_MD5_128": "MD5 is collision-broken",
    "AUTH_KPDK_MD5": "MD5-based, withdrawn",
    "AUTH_DES_MAC": "DES-based MAC, withdrawn",
    "AUTH_NONE": "no integrity protection on a non-AEAD SA",
    # IKEv1 integrity names, derived from the phase-1 Hash attribute
    "AUTH_HMAC_MD5": "MD5 is collision-broken; MUST NOT per RFC 8247",
    "AUTH_HMAC_TIGER": "unanalysed, no current implementation requirement",
}

INTEG_LEGACY = {
    "AUTH_HMAC_SHA1_96": "SHA-1 is deprecated for new systems (SP 800-131A Rev. 2)",
    "AUTH_HMAC_SHA1_160": "SHA-1 is deprecated for new systems",
    "AUTH_HMAC_SHA1": "SHA-1 is deprecated for new systems",
}

PRF_PROHIBITED = {
    "PRF_HMAC_MD5": "MD5-based PRF, MUST NOT per RFC 8247",
    "PRF_HMAC_TIGER": "unanalysed, no implementation requirement",
}

PRF_LEGACY = {
    "PRF_HMAC_SHA1": "SHA-1-based PRF is deprecated for new systems",
}

# --------------------------------------------------------------------------
# Key exchange
# --------------------------------------------------------------------------

MIN_DH_BITS = 2048  # classical security equivalent

DH_PROHIBITED = {
    1: "768-bit MODP: factorable with modest resources; MUST NOT",
    2: "1024-bit MODP: within reach of nation-state precomputation (Logjam)",
    22: "1024-bit MODP subgroup: same weakness as Group 2",
    25: "192-bit ECP: below the 112-bit security floor",
}

DH_LEGACY = {
    5: "1536-bit MODP: below the 2048-bit floor of SP 800-77 Rev. 1",
    26: "224-bit ECP: minimum acceptable, prefer Group 19 or 31",
}

DH_PQ_GROUPS = {35, 36, 37}  # ML-KEM hybrids

# --------------------------------------------------------------------------
# Authentication and session policy
# --------------------------------------------------------------------------

WEAK_AUTH = {
    "PRE_SHARED_KEY": "PSK authentication is offline-crackable if a handshake is captured",
    "XAUTH_INIT_PRESHARED": "PSK-derived XAUTH, offline-crackable",
    "HYBRID_INIT_RSA": "hybrid mode leaves the initiator unauthenticated at phase 1",
}

MAX_IKE_SA_LIFETIME = 86400  # 24h
MAX_CHILD_SA_LIFETIME = 28800  # 8h

# --------------------------------------------------------------------------
# ESP framing classes.
#
# Suites sharing IV length, ICV length and block size are indistinguishable from
# packet framing alone, so the engine reasons about the class rather than
# claiming a specific suite. Every class carries a verdict that holds for all of
# its members — which is why an ambiguous inference still yields a firm finding.
# --------------------------------------------------------------------------

FRAMING_CLASSES = {
    "64-bit block cipher": {
        "members": ["3DES-CBC / HMAC-MD5-96", "DES-CBC / HMAC-SHA1-96"],
        "signature": "block 8, IV 8, ICV 12",
        "verdict": "prohibited",
        "reason": "64-bit block size is vulnerable to Sweet32 birthday collisions "
        "on long-lived tunnels; both DES and 3DES are withdrawn.",
    },
    "AES-CBC with 96-bit ICV": {
        "members": ["AES-CBC-128 / HMAC-SHA1-96"],
        "signature": "block 16, IV 16, ICV 12",
        "verdict": "legacy",
        "reason": "SHA-1 truncated to 96 bits; CBC lacks integrated authentication.",
    },
    "AES-CBC with 128-bit ICV": {
        "members": ["AES-CBC-256 / HMAC-SHA2-256-128"],
        "signature": "block 16, IV 16, ICV 16",
        "verdict": "acceptable",
        "reason": "Sound but not AEAD; migrate to AES-GCM when the platform allows.",
    },
    "AEAD or counter mode": {
        "members": [
            "AES-CTR-128 / HMAC-SHA2-256-128",
            "AES-GCM-128 (ICV 16)",
            "AES-GCM-256 (ICV 16)",
            "ChaCha20-Poly1305",
        ],
        "signature": "block 1 (4-byte aligned), IV 8, ICV 16",
        "verdict": "acceptable",
        "reason": "Modern construction. The exact member cannot be resolved from "
        "framing alone, but every member meets the baseline.",
    },
    "unencrypted payload": {
        "members": ["NULL encryption / HMAC-SHA1-96"],
        "signature": "no IV, ICV 12, low payload entropy",
        "verdict": "prohibited",
        "reason": "ESP-NULL provides integrity only. Traffic crosses the link in "
        "plaintext and is readable by anyone on path.",
    },
}


def framing_class_of(suite: str) -> tuple[str, dict] | tuple[None, None]:
    for name, spec in FRAMING_CLASSES.items():
        if suite in spec["members"]:
            return name, spec
    return None, None
