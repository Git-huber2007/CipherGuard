"""IANA registry tables for IKEv1 / IKEv2 / ESP.

References:
  RFC 7296  Internet Key Exchange Protocol Version 2 (IKEv2)
  RFC 4303  IP Encapsulating Security Payload (ESP)
  RFC 2409  The Internet Key Exchange (IKEv1)
  RFC 8247  Algorithm Implementation Requirements for IKEv2
  RFC 9242  Intermediate Exchange in IKEv2
  RFC 9370  Multiple Key Exchanges in IKEv2
  IANA "Internet Key Exchange Version 2 (IKEv2) Parameters"
"""

from __future__ import annotations

# --------------------------------------------------------------------------
# IKE header
# --------------------------------------------------------------------------

IKE_HEADER_LEN = 28
IKE_VERSION_1 = 0x10
IKE_VERSION_2 = 0x20

EXCHANGE_TYPES_V2 = {
    34: "IKE_SA_INIT",
    35: "IKE_AUTH",
    36: "CREATE_CHILD_SA",
    37: "INFORMATIONAL",
    # RFC 9242: carries data too large for IKE_SA_INIT, between it and IKE_AUTH.
    # RFC 9370 uses it for each additional key exchange. Encrypted from the
    # first byte after the header, so only its occurrence is observable.
    43: "IKE_INTERMEDIATE",
    # RFC 9370: additional key exchanges after a CREATE_CHILD_SA. Also encrypted.
    44: "IKE_FOLLOWUP_KE",
}

EXCHANGE_TYPES_V1 = {
    0: "NONE",
    1: "Base",
    2: "Identity Protection (Main Mode)",
    3: "Authentication Only",
    4: "Aggressive Mode",
    5: "Informational",
    32: "Quick Mode",
}

FLAG_INITIATOR = 0x08
FLAG_VERSION = 0x10
FLAG_RESPONSE = 0x20

# --------------------------------------------------------------------------
# IKEv2 payload types (RFC 7296 s3.2)
# --------------------------------------------------------------------------

PAYLOAD_V2 = {
    0: "NONE",
    33: "SA",
    34: "KE",
    35: "IDi",
    36: "IDr",
    37: "CERT",
    38: "CERTREQ",
    39: "AUTH",
    40: "NONCE",
    41: "NOTIFY",
    42: "DELETE",
    43: "VENDOR_ID",
    44: "TSi",
    45: "TSr",
    46: "SK",
    47: "CP",
    48: "EAP",
    53: "SKF",
}

PAYLOAD_SA_V2 = 33
PAYLOAD_KE_V2 = 34
PAYLOAD_NONCE_V2 = 40
PAYLOAD_NOTIFY_V2 = 41
PAYLOAD_VID_V2 = 43

# IKEv1 payload types (RFC 2408 s3.1)
PAYLOAD_V1 = {
    0: "NONE",
    1: "SA",
    2: "PROPOSAL",
    3: "TRANSFORM",
    4: "KE",
    5: "ID",
    6: "CERT",
    7: "CERTREQ",
    8: "HASH",
    9: "SIG",
    10: "NONCE",
    11: "NOTIFY",
    12: "DELETE",
    13: "VENDOR_ID",
}

PAYLOAD_SA_V1 = 1
PAYLOAD_KE_V1 = 4
PAYLOAD_NONCE_V1 = 10
PAYLOAD_VID_V1 = 13

PROTOCOL_IDS = {1: "IKE", 2: "AH", 3: "ESP", 4: "FC_ESP_HEADER"}

# --------------------------------------------------------------------------
# IKEv2 transform types and IDs (RFC 7296 s3.3.2)
# --------------------------------------------------------------------------

# RFC 9370 s2 adds seven "Additional Key Exchange" transform types, 6 to 12.
# Each names one more key exchange to run after the first, and takes its
# transform IDs from the same registry as type 4. ID 0 (NONE) in one of them
# means that slot is not used.
TRANSFORM_KE = 4
ADDKE_TRANSFORM_TYPES = (6, 7, 8, 9, 10, 11, 12)
KE_TRANSFORM_TYPES = (TRANSFORM_KE,) + ADDKE_TRANSFORM_TYPES

TRANSFORM_TYPE = {
    1: "ENCR",
    2: "PRF",
    3: "INTEG",
    4: "DH",
    5: "ESN",
    6: "ADDKE1",
    7: "ADDKE2",
    8: "ADDKE3",
    9: "ADDKE4",
    10: "ADDKE5",
    11: "ADDKE6",
    12: "ADDKE7",
}

ENCR = {
    1: "ENCR_DES_IV64",
    2: "ENCR_DES",
    3: "ENCR_3DES",
    4: "ENCR_RC5",
    5: "ENCR_IDEA",
    6: "ENCR_CAST",
    7: "ENCR_BLOWFISH",
    8: "ENCR_3IDEA",
    9: "ENCR_DES_IV32",
    11: "ENCR_NULL",
    12: "ENCR_AES_CBC",
    13: "ENCR_AES_CTR",
    14: "ENCR_AES_CCM_8",
    15: "ENCR_AES_CCM_12",
    16: "ENCR_AES_CCM_16",
    18: "ENCR_AES_GCM_8",
    19: "ENCR_AES_GCM_12",
    20: "ENCR_AES_GCM_16",
    21: "ENCR_NULL_AUTH_AES_GMAC",
    23: "ENCR_CAMELLIA_CBC",
    24: "ENCR_CAMELLIA_CTR",
    25: "ENCR_CAMELLIA_CCM_8",
    26: "ENCR_CAMELLIA_CCM_12",
    27: "ENCR_CAMELLIA_CCM_16",
    28: "ENCR_CHACHA20_POLY1305",
}

PRF = {
    1: "PRF_HMAC_MD5",
    2: "PRF_HMAC_SHA1",
    3: "PRF_HMAC_TIGER",
    4: "PRF_AES128_XCBC",
    5: "PRF_HMAC_SHA2_256",
    6: "PRF_HMAC_SHA2_384",
    7: "PRF_HMAC_SHA2_512",
    8: "PRF_AES128_CMAC",
}

INTEG = {
    0: "AUTH_NONE",
    1: "AUTH_HMAC_MD5_96",
    2: "AUTH_HMAC_SHA1_96",
    3: "AUTH_DES_MAC",
    4: "AUTH_KPDK_MD5",
    5: "AUTH_AES_XCBC_96",
    6: "AUTH_HMAC_MD5_128",
    7: "AUTH_HMAC_SHA1_160",
    8: "AUTH_AES_CMAC_96",
    9: "AUTH_AES_128_GMAC",
    10: "AUTH_AES_192_GMAC",
    11: "AUTH_AES_256_GMAC",
    12: "AUTH_HMAC_SHA2_256_128",
    13: "AUTH_HMAC_SHA2_384_192",
    14: "AUTH_HMAC_SHA2_512_256",
}

# Diffie-Hellman groups. "bits" is the classical security-equivalent modulus
# size; "pq" marks the ML-KEM hybrid groups from the post-quantum registry.
DH_GROUPS = {
    0: {"name": "NONE", "bits": 0, "kind": "none"},
    1: {"name": "768-bit MODP", "bits": 768, "kind": "modp"},
    2: {"name": "1024-bit MODP", "bits": 1024, "kind": "modp"},
    5: {"name": "1536-bit MODP", "bits": 1536, "kind": "modp"},
    14: {"name": "2048-bit MODP", "bits": 2048, "kind": "modp"},
    15: {"name": "3072-bit MODP", "bits": 3072, "kind": "modp"},
    16: {"name": "4096-bit MODP", "bits": 4096, "kind": "modp"},
    17: {"name": "6144-bit MODP", "bits": 6144, "kind": "modp"},
    18: {"name": "8192-bit MODP", "bits": 8192, "kind": "modp"},
    19: {"name": "256-bit random ECP", "bits": 3072, "kind": "ecp"},
    20: {"name": "384-bit random ECP", "bits": 7680, "kind": "ecp"},
    21: {"name": "521-bit random ECP", "bits": 15360, "kind": "ecp"},
    22: {"name": "1024-bit MODP / 160-bit POS", "bits": 1024, "kind": "modp"},
    23: {"name": "2048-bit MODP / 224-bit POS", "bits": 2048, "kind": "modp"},
    24: {"name": "2048-bit MODP / 256-bit POS", "bits": 2048, "kind": "modp"},
    25: {"name": "192-bit random ECP", "bits": 1536, "kind": "ecp"},
    26: {"name": "224-bit random ECP", "bits": 2048, "kind": "ecp"},
    27: {"name": "brainpoolP224r1", "bits": 2048, "kind": "ecp"},
    28: {"name": "brainpoolP256r1", "bits": 3072, "kind": "ecp"},
    29: {"name": "brainpoolP384r1", "bits": 7680, "kind": "ecp"},
    30: {"name": "brainpoolP512r1", "bits": 15360, "kind": "ecp"},
    31: {"name": "Curve25519", "bits": 3072, "kind": "ecp"},
    32: {"name": "Curve448", "bits": 7680, "kind": "ecp"},
    35: {"name": "ML-KEM-512", "bits": 3072, "kind": "pq"},
    36: {"name": "ML-KEM-768", "bits": 7680, "kind": "pq"},
    37: {"name": "ML-KEM-1024", "bits": 15360, "kind": "pq"},
}

ESN = {0: "NO_ESN", 1: "ESN"}

# None: the key exchange types are named from DH_GROUPS, not from a flat table.
TRANSFORM_TABLES = {1: ENCR, 2: PRF, 3: INTEG, 4: None, 5: ESN, **{t: None for t in ADDKE_TRANSFORM_TYPES}}

ATTR_KEY_LENGTH = 14  # RFC 7296 s3.3.5

# --------------------------------------------------------------------------
# IKEv1 phase-1 SA attributes (RFC 2409 Appendix A)
# --------------------------------------------------------------------------

V1_ATTR = {
    1: "Encryption Algorithm",
    2: "Hash Algorithm",
    3: "Authentication Method",
    4: "Group Description",
    5: "Group Type",
    11: "Life Type",
    12: "Life Duration",
    14: "Key Length",
}

V1_ENCR = {
    1: "DES_CBC",
    2: "IDEA_CBC",
    3: "BLOWFISH_CBC",
    4: "RC5_R16_B64_CBC",
    5: "3DES_CBC",
    6: "CAST_CBC",
    7: "AES_CBC",
    8: "CAMELLIA_CBC",
}

V1_HASH = {
    1: "MD5",
    2: "SHA1",
    3: "TIGER",
    4: "SHA2_256",
    5: "SHA2_384",
    6: "SHA2_512",
}

V1_AUTH = {
    1: "PRE_SHARED_KEY",
    2: "DSS_SIGNATURES",
    3: "RSA_SIGNATURES",
    4: "RSA_ENCRYPTION",
    5: "REVISED_RSA_ENCRYPTION",
    64221: "HYBRID_INIT_RSA",
    65001: "XAUTH_INIT_PRESHARED",
}

V1_LIFE_TYPE = {1: "seconds", 2: "kilobytes"}

# --------------------------------------------------------------------------
# Vendor ID fingerprints. Keys are lowercase hex prefixes of the VID payload.
# --------------------------------------------------------------------------

VENDOR_IDS = {
    "4048b7d56ebce88525e7de7f00d6c2d3": "IKE Fragmentation (draft-ietf-ipsec-heartbeats)",
    "afcad71368a1f1c96b8696fc77570100": "Dead Peer Detection (RFC 3706)",
    "4a131c81070358455c5728f20e95452f": "NAT-T (RFC 3947)",
    "90cb80913ebb696e086381b5ec427b1f": "NAT-T draft-ietf-ipsec-nat-t-ike-02\\n",
    "4f45367273746572": "strongSwan",
    "882fe56d6fd20dbc2251613b2ebe5beb": "strongSwan",
    "12f5f28c457168a9702d9fe274cc0100": "Cisco Unity",
    "cbe7943665ff6c2cd39a11f56aad86a0": "Cisco IOS / ASA",
    "1f07f70eaa6514d3b0fa96542a500100": "Cisco VPN 3000 Concentrator",
    "8404ad0330a7e4a41325229166d0cfff": "Fortinet FortiGate",
    "0d33611a5d521b5e3c9c03d2fc107e12": "Juniper SRX / NetScreen",
    "699369228741c6d4ca094c93e242c9de": "Microsoft Windows IKE",
    "4865617274426561745f4e6f74696679": "HeartBeat Notify",
}

VENDOR_FAMILY = {
    "Cisco Unity": "cisco",
    "Cisco IOS / ASA": "cisco",
    "Cisco VPN 3000 Concentrator": "cisco",
    "Fortinet FortiGate": "fortinet",
    "Juniper SRX / NetScreen": "juniper",
    "strongSwan": "strongswan",
    "Microsoft Windows IKE": "windows",
}

# --------------------------------------------------------------------------
# ESP cipher suite catalogue used by the inference model.
#
# block   : cipher block size in bytes (1 = stream / counter mode)
# iv      : explicit per-packet IV or nonce carried in the ESP payload
# icv     : integrity check value length appended to the ciphertext
# aead    : combined-mode algorithm (no separate INTEG transform)
# --------------------------------------------------------------------------

ESP_SUITES = {
    "AES-CBC-128 / HMAC-SHA1-96": dict(block=16, iv=16, icv=12, aead=False),
    "AES-CBC-256 / HMAC-SHA2-256-128": dict(block=16, iv=16, icv=16, aead=False),
    "AES-CTR-128 / HMAC-SHA2-256-128": dict(block=1, iv=8, icv=16, aead=False),
    "AES-GCM-128 (ICV 16)": dict(block=1, iv=8, icv=16, aead=True),
    "AES-GCM-256 (ICV 16)": dict(block=1, iv=8, icv=16, aead=True),
    "ChaCha20-Poly1305": dict(block=1, iv=8, icv=16, aead=True),
    "3DES-CBC / HMAC-MD5-96": dict(block=8, iv=8, icv=12, aead=False),
    "DES-CBC / HMAC-SHA1-96": dict(block=8, iv=8, icv=12, aead=False),
    "NULL encryption / HMAC-SHA1-96": dict(block=1, iv=0, icv=12, aead=False),
}

ESP_SUITE_LABELS = list(ESP_SUITES.keys())
