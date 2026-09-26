"""The analysis payload: built here once, for every client.

The API, the live-sniffer snapshot and the static GitHub Pages export all hand
the dashboard the same document. It used to be assembled in each place
separately, which is how two clients end up disagreeing about a capture. Now
each of them calls build_payload() and adds only what is genuinely theirs (the
static export bakes remediation text, because it has no server to ask later).

Provenance is computed here, server-side, and never in the browser: a hash the
page computed about data the page was given proves nothing about the capture on
disk or the model that assessed it.
"""

from __future__ import annotations

import hashlib
import json
import os
from typing import Any

from ..core.audit_log import _digest
from ..core.models import Assessment
from ..intel.pqc import roadmap
from ..pipeline import throughput_estimate
from ..remediation.synth import PLATFORM_NAMES, detect_platforms

REPORT_DIGEST_COVERS = (
    "SHA-256 over the sorted rule-ID:subject pair of every finding, first 16 hex "
    "digits. Two reports with the same digest raised the same findings on the "
    "same links."
)


def model_provenance(model_dir: str) -> dict[str, Any] | None:
    """The manifest hash and training date of the model in `model_dir`.

    The manifest is what the loader verifies every model file against before
    unpickling, so its hash identifies the exact model files that were used.
    """
    manifest = os.path.join(model_dir, "MANIFEST.sha256")
    if not os.path.isfile(manifest):
        return None
    with open(manifest, "rb") as fh:
        manifest_sha256 = hashlib.sha256(fh.read()).hexdigest()
    trained_at = None
    try:
        with open(os.path.join(model_dir, "meta.json"), encoding="utf-8") as fh:
            trained_at = json.load(fh).get("provenance", {}).get("trained_at")
    except (OSError, ValueError):
        pass
    return {"manifest_sha256": manifest_sha256, "trained_at": trained_at}


def provenance(assessment: Assessment, capture_path: str, model_dir: str) -> dict[str, Any]:
    return {
        "capture": os.path.basename(capture_path),
        "capture_sha256": _digest(capture_path),
        # only a model the analysis actually loaded (and so verified) is named
        "model": model_provenance(model_dir) if assessment.stats.get("model_loaded") else None,
        "report_digest": assessment.digest(),
        "report_digest_covers": REPORT_DIGEST_COVERS,
    }


def build_payload(assessment: Assessment, capture_path: str, model_dir: str) -> dict[str, Any]:
    payload = assessment.to_dict()
    payload["throughput"] = throughput_estimate(assessment)
    payload["platforms"] = [
        {"id": p, "name": PLATFORM_NAMES[p]} for p in detect_platforms(assessment)
    ]
    payload["roadmap"] = roadmap(assessment)
    payload["provenance"] = provenance(assessment, capture_path, model_dir)
    return payload
