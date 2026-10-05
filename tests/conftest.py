"""Shared test fixtures.

The ESP rules can only fire when an inference model exists, so tests that
exercise them depend on one. Relying on a `models/` directory left behind by a
previous run makes the suite pass or fail according to the state of the working
tree, which hides exactly the kind of regression the suite is there to catch —
a clean checkout would have skipped the ESP path entirely and still reported
green. So the suite trains its own model, once, into a temporary directory.

It is deliberately small: enough samples and epochs for the framing signal to
be learned reliably, not enough to make the suite slow.
"""

from __future__ import annotations

import pytest


@pytest.fixture(scope="session")
def model_dir(tmp_path_factory) -> str:
    from cipherguard.ml.train import train

    out = str(tmp_path_factory.mktemp("models"))
    train(samples_per_suite=25, epochs=12, seed=7, out=out, verbose=False)
    return out


@pytest.fixture(autouse=True)
def _point_analysis_at_the_test_model(monkeypatch, request):
    """Redirect the pipeline's default model directory at the session model.

    autouse keeps individual tests from having to thread the path through, and
    only tests that actually run the pipeline pay the training cost, because the
    session fixture is resolved lazily on first use.
    """
    if "no_model" in request.keywords:
        return
    import cipherguard.pipeline as pipeline

    resolved = request.getfixturevalue("model_dir")
    monkeypatch.setattr(pipeline, "DEFAULT_MODEL_DIR", resolved)

    original = pipeline.analyze

    def analyze_with_test_model(capture, model_dir=None, **kwargs):
        return original(capture, model_dir=model_dir or resolved, **kwargs)

    monkeypatch.setattr(pipeline, "analyze", analyze_with_test_model)


@pytest.fixture(autouse=True)
def _test_client_host_is_local(monkeypatch):
    """Starlette's TestClient addresses the app as "testserver".

    A tokenless app answers loopback names only, so the test client's name is
    added here rather than in the product. test_api_security.py sends explicit
    Host headers to check the allowlist itself.
    """
    from cipherguard.api import security

    monkeypatch.setattr(security, "LOOPBACK_HOSTS", security.LOOPBACK_HOSTS | {"testserver"})


def pytest_report_header(config):
    """Say plainly whether the strongest validation claim is actually running.

    The real-capture tests skip when the corpus is absent, and a `-q` run still
    prints "passed" — so the one externally-grounded claim in the project can
    silently not execute while the summary looks clean. A skip that nobody sees
    is indistinguishable from a pass.
    """
    from cipherguard.lab import realworld

    present = realworld.available()
    if present:
        return f"real-capture validation: ENABLED ({len(present)} captures)"
    return (
        "real-capture validation: SKIPPED - no captures in samples/real/. "
        "The external validation tests will NOT run. "
        "Fetch with: ./scripts/fetch-real-captures.sh"
    )
