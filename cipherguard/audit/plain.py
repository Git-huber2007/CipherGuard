"""One sentence per rule, for a reader who is not an IPsec specialist.

The technical detail on each finding is written for the engineer who fixes it.
The people who decide whether it gets fixed — a programme lead, a judge, a
minister's adviser — need to know what the risk *is* before they need to know
which transform caused it. These sentences say that, with no protocol
vocabulary inside them.

They are keyed by rule, not by finding, so every finding a rule raises carries
the same explanation, and the dashboard gets it from here rather than writing
its own. A test fails if a rule in the catalogue has no sentence.
"""

from __future__ import annotations

WHY_IT_MATTERS: dict[str, str] = {
    "IKE-001": "The tunnel is set up with an old version of its protocol that has known "
               "design weaknesses and is no longer recommended for government networks.",
    "IKE-002": "The way this tunnel starts up lets an eavesdropper try to guess its shared "
               "password offline, as many times as they like, without being noticed.",
    "IKE-003": "The two ends prove who they are with a single shared password, so anyone who "
               "learns it can pretend to be either end.",
    "IKE-004": "The encryption protecting the tunnel's start-up is officially retired as too "
               "weak, so traffic recorded today may be readable to an attacker.",
    "IKE-005": "The check that detects tampering is retired or weakened, so an attacker may be "
               "able to change messages without anyone noticing.",
    "IKE-006": "The method the two ends use to agree a secret key is too weak by current "
               "standards, so a well-resourced attacker could work the key out.",
    "IKE-007": "Traffic recorded today could be decrypted once large quantum computers exist, "
               "which matters for anything that has to stay secret for years.",
    "IKE-008": "The device still offers weak options, so an attacker in the middle could push "
               "the connection onto them even when today's session is strong.",
    "IKE-009": "Each key stays in use for too long, so one stolen key would expose more traffic "
               "than it should.",
    "IKE-010": "The tunnel repeatedly failed to start, which can mean a configuration mistake "
               "or someone deliberately interfering with the connection.",
    "IKE-011": "Large start-up messages may be split or dropped along the way, which can stop "
               "the tunnel from coming up reliably.",
    "IKE-012": "A connection is only as strong as its weakest part, and one part of this one is "
               "below the level required for sensitive information.",
    "IKE-013": "The encryption in use becomes unsafe after a certain amount of traffic, and this "
               "link has already carried enough to reach that point.",
    "ESP-001": "Judging by the shape of the protected traffic, it is using weak encryption or "
               "none at all.",
    "ESP-002": "The traffic looks less random than properly encrypted data should, which "
               "suggests it may not be encrypted.",
    "ESP-003": "Gaps in the traffic's numbering can mean lost data, or someone replaying or "
               "removing messages.",
    "ESP-004": "The tool could not tell with confidence how this traffic is protected, so a "
               "person should check the device's settings directly.",
}


def why_it_matters(rule_id: str) -> str | None:
    return WHY_IT_MATTERS.get(rule_id)
