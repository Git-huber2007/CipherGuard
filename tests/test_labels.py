"""User-labelled real captures: label format, label-check, and real-flow training.

The captures here are written by the synthetic pcap emitter, because a test
suite cannot ship somebody's real tunnel. What is under test is the plumbing a
real capture goes through — sidecar parsing, flow matching, framing-class
scoring, leave-one-capture-out isolation and provenance — not the accuracy
figure, which only real captures can supply.
"""

from __future__ import annotations

import json
import os

import pytest

from cipherguard.core.models import EspFlow
from cipherguard.lab import labels as L
from cipherguard.ml.classifier import (
    SYNTHETIC_CORPUS,
    Prediction,
    corpus_composition,
)
from cipherguard.ml.synth import write_esp_pcap
from cipherguard.ml.train import LeakageError, leave_one_capture_out

GCM = "AES-GCM-256 (ICV 16)"
CBC = "AES-CBC-128 / HMAC-SHA1-96"
TDES = "3DES-CBC / HMAC-MD5-96"
SOURCE = "swanctl --list-sas on the responder"


def _capture(directory, name, suite, seed=3, src="203.0.113.10",
             dst="198.51.100.20", packets=300, label=None):
    path = os.path.join(str(directory), name)
    write_esp_pcap(path, suite, packets=packets, seed=seed, src=src, dst=dst)
    if label is not None:
        with open(L.label_path(path), "w", encoding="utf-8") as fh:
            json.dump(label, fh)
    return path


def _peer_label(suite, src="203.0.113.10", dst="198.51.100.20", source=SOURCE):
    return {"source": source, "flows": [{"peers": [src, dst], "suite": suite}]}


# ---------------------------------------------------------------------------
# Label format
# ---------------------------------------------------------------------------


@pytest.mark.no_model
def test_label_parses_spi_in_the_forms_endpoints_print():
    label = L.parse_label(
        {"source": SOURCE, "flows": [
            {"spi": "c3a1f00d", "suite": GCM},
            {"spi": "0xC3A1F00E", "suite": GCM},
            {"spi": 42, "suite": CBC, "dst": "10.0.0.1"},
        ]},
        "x.pcap",
    )
    assert [e.spi for e in label.entries] == [0xC3A1F00D, 0xC3A1F00E, 42]
    assert label.entries[2].dst == "10.0.0.1"


@pytest.mark.no_model
@pytest.mark.parametrize("data, needle", [
    ({"source": SOURCE, "flows": [{"spi": 1, "suite": "AES-GCM-512"}]}, "not in the catalogue"),
    ({"flows": [{"spi": 1, "suite": GCM}]}, "no 'source'"),
    ({"source": "  ", "flows": [{"spi": 1, "suite": GCM}]}, "no 'source'"),
    ({"source": SOURCE, "flows": [{"suite": GCM}]}, "exactly one of"),
    ({"source": SOURCE, "flows": [{"spi": 1, "peers": ["a", "b"], "suite": GCM}]},
     "exactly one of"),
    ({"source": SOURCE, "flows": [{"spi": 1, "suite": GCM}, {"spi": 1, "suite": CBC}]},
     "labelled twice"),
    ({"source": SOURCE, "flows": [{"peers": ["a", "a"], "suite": GCM}]}, "two distinct"),
    ({"source": SOURCE, "flows": [{"spi": 0, "suite": GCM}]}, "32-bit"),
    ({"source": SOURCE, "flows": []}, "non-empty"),
])
def test_malformed_labels_are_rejected_with_a_reason(data, needle):
    with pytest.raises(L.LabelError, match=needle):
        L.parse_label(data, "x.pcap")


@pytest.mark.no_model
def test_per_entry_source_overrides_the_capture_source():
    label = L.parse_label(
        {"source": SOURCE, "flows": [
            {"spi": 1, "suite": GCM},
            {"spi": 2, "suite": GCM, "source": "ip xfrm state on the initiator"},
        ]},
        "x.pcap",
    )
    assert [e.source for e in label.entries] == [SOURCE, "ip xfrm state on the initiator"]


@pytest.mark.no_model
def test_spi_entry_beats_peer_entry_and_peers_match_both_directions():
    label = L.parse_label(
        {"source": SOURCE, "flows": [
            {"peers": ["10.0.0.1", "10.0.0.2"], "suite": CBC},
            {"spi": 7, "suite": GCM},
        ]},
        "x.pcap",
    )
    forward = EspFlow(spi=7, src="10.0.0.1", dst="10.0.0.2")
    reverse = EspFlow(spi=8, src="10.0.0.2", dst="10.0.0.1")
    other = EspFlow(spi=9, src="10.0.0.3", dst="10.0.0.2")
    assert label.entry_for(forward).suite == GCM
    assert label.entry_for(reverse).suite == CBC
    assert label.entry_for(other) is None


@pytest.mark.no_model
def test_malformed_json_sidecar_is_an_error_not_an_unlabelled_capture(tmp_path):
    path = _capture(tmp_path, "a.pcap", GCM)
    with open(L.label_path(path), "w") as fh:
        fh.write("{not json")
    with pytest.raises(L.LabelError, match="not valid JSON"):
        L.load_label(path)


# ---------------------------------------------------------------------------
# Corpus collection: nothing is dropped silently
# ---------------------------------------------------------------------------


@pytest.mark.no_model
def test_collect_reports_unlabelled_captures_and_dead_label_entries(tmp_path):
    _capture(tmp_path, "a.pcap", GCM, label=_peer_label(GCM))
    _capture(tmp_path, "b.pcap", CBC, seed=5)  # no sidecar
    _capture(tmp_path, "c.pcap", CBC, seed=6, label={
        "source": SOURCE,
        "flows": [{"peers": ["203.0.113.10", "198.51.100.20"], "suite": CBC},
                  {"spi": "deadbeef", "suite": GCM}],
    })
    (tmp_path / "notes.txt").write_text("not a capture")

    corpus = L.collect(str(tmp_path))
    assert corpus.captures == ["a.pcap", "c.pcap"]
    assert corpus.unlabelled == ["b.pcap"]
    assert [s.suite for s in corpus.samples] == [GCM, CBC]
    assert all(s.source == SOURCE for s in corpus.samples)
    assert corpus.unmatched_entries == [
        {"capture": "c.pcap", "label": "SPI 0xdeadbeef", "suite": GCM}
    ]


@pytest.mark.no_model
def test_collect_reports_labelled_capture_that_contributes_nothing(tmp_path):
    _capture(tmp_path, "short.pcap", GCM, packets=4, label=_peer_label(GCM))
    _capture(tmp_path, "wrongpeer.pcap", GCM, label=_peer_label(GCM, src="10.9.9.9"))
    corpus = L.collect(str(tmp_path))
    assert not corpus.samples
    reasons = {e["capture"]: e["reason"] for e in corpus.empty}
    assert "fewer than 8 packets" in reasons["short.pcap"]
    assert "matches any ESP flow" in reasons["wrongpeer.pcap"]


# ---------------------------------------------------------------------------
# label-check
# ---------------------------------------------------------------------------


def test_label_check_hits_on_a_correct_label(tmp_path, model_dir):
    from cipherguard.ml.classifier import SuiteClassifier

    path = _capture(tmp_path, "gcm.pcap", GCM, packets=400, label=_peer_label(GCM))
    result = L.check_capture(path, SuiteClassifier.load(model_dir))
    assert result["labelled"] and result["passed"]
    assert result["hits"] == 1 and result["misses"] == 0
    row = result["results"][0]
    assert row["label_class"] == row["predicted_class"] == "AEAD or counter mode"
    assert row["label_source"] == SOURCE


def test_label_check_miss_carries_the_plausibility_exclusions(tmp_path, model_dir):
    """A GCM tunnel mislabelled as 3DES: the mask must say why 3DES is
    impossible, in stated reasons, rather than just reporting a mismatch."""
    from cipherguard.ml.classifier import SuiteClassifier

    path = _capture(tmp_path, "wrong.pcap", GCM, packets=400, label=_peer_label(TDES))
    result = L.check_capture(path, SuiteClassifier.load(model_dir))
    assert not result["passed"] and result["misses"] == 1

    miss = result["results"][0]["miss"]
    excluded_suites = {e["suite"] for e in miss["truth_excluded"]}
    assert TDES in excluded_suites
    assert all(e["reason"] for e in miss["all_exclusions"])
    assert "ruled out every member" in miss["diagnosis"]


def test_label_check_reports_an_unlabelled_capture(tmp_path, model_dir):
    from cipherguard.ml.classifier import SuiteClassifier

    path = _capture(tmp_path, "bare.pcap", GCM)
    result = L.check_capture(path, SuiteClassifier.load(model_dir))
    assert result["labelled"] is False
    assert result["passed"] is False


def test_label_check_cli(tmp_path, model_dir, capsys):
    from cipherguard.cli import main

    good = _capture(tmp_path, "gcm.pcap", GCM, packets=400, label=_peer_label(GCM))
    bare = _capture(tmp_path, "bare.pcap", GCM)

    assert main(["--models", model_dir, "label-check", good]) == 0
    assert "PASS" in capsys.readouterr().out

    assert main(["--models", model_dir, "label-check", bare]) == 1
    assert "UNLABELLED" in capsys.readouterr().out


def test_verify_real_reports_esp_separately_and_lists_unlabelled(tmp_path, model_dir, capsys):
    from cipherguard.cli import main

    _capture(tmp_path, "gcm.pcap", GCM, packets=400, label=_peer_label(GCM))
    _capture(tmp_path, "mystery.pcap", CBC, seed=9)

    code = main(["--models", model_dir, "verify-real", "--dir", str(tmp_path)])
    out = capsys.readouterr().out
    assert "IKE dissector" in out and "ESP inference" in out
    assert "ESP: 1/1 flows correct" in out
    assert "mystery.pcap" in out and "unlabelled" in out
    assert code == 0


# ---------------------------------------------------------------------------
# Leave-one-capture-out
# ---------------------------------------------------------------------------


class _RecordingModel:
    """Remembers exactly which flows it was trained on, and refuses to score one."""

    def __init__(self, trained: list):
        self.trained = {id(s.flow) for s in trained}
        self.scored: list[int] = []

    def predict_one(self, flow):
        assert id(flow) not in self.trained, "scored a flow this model trained on"
        self.scored.append(id(flow))
        return Prediction(label=GCM, confidence=1.0, ranked=[(GCM, 1.0)],
                          group=[GCM], group_confidence=1.0, excluded=[])


def _samples(spec: dict[str, int]) -> list:
    out = []
    for capture, n in spec.items():
        for i in range(n):
            flow = EspFlow(spi=len(out) + 1, src="10.0.0.1", dst=f"10.0.{i}.2",
                           payload_lengths=[100] * 20, packets=20)
            out.append(L.RealSample(capture=capture, flow=flow, suite=GCM, source=SOURCE))
    return out


@pytest.mark.no_model
def test_leave_one_capture_out_never_scores_a_flow_on_a_model_trained_with_it():
    samples = _samples({"a.pcap": 3, "b.pcap": 1, "c.pcap": 4})
    models: list[_RecordingModel] = []

    def fit(train_set):
        models.append(_RecordingModel(train_set))
        return models[-1]

    result = leave_one_capture_out(samples, fit)

    # one model per capture, and each saw no flow from the capture it scored
    assert len(models) == 3
    by_capture = {c: {id(s.flow) for s in samples if s.capture == c}
                  for c in ("a.pcap", "b.pcap", "c.pcap")}
    for model, capture in zip(models, sorted(by_capture)):
        assert set(model.scored) == by_capture[capture]
        assert not model.trained & by_capture[capture]
        # ...and did train on every other capture's flows
        others = set().union(*(v for k, v in by_capture.items() if k != capture))
        assert model.trained == others

    # every real flow scored exactly once
    scored = [f for m in models for f in m.scored]
    assert sorted(scored) == sorted(id(s.flow) for s in samples)
    assert result["flows"] == 8 and result["captures"] == 3
    assert result["method"] == "leave-one-capture-out"


@pytest.mark.no_model
def test_leave_one_capture_out_refuses_a_flow_shared_between_captures():
    samples = _samples({"a.pcap": 1, "b.pcap": 1})
    samples.append(L.RealSample(capture="b.pcap", flow=samples[0].flow,
                                suite=GCM, source=SOURCE))
    with pytest.raises(LeakageError):
        leave_one_capture_out(samples, lambda train_set: _RecordingModel(train_set))


@pytest.mark.no_model
def test_single_capture_fold_trains_on_no_real_flows():
    samples = _samples({"only.pcap": 2})
    seen = []
    leave_one_capture_out(samples, lambda t: seen.append(list(t)) or _RecordingModel(t))
    assert seen == [[]]


# ---------------------------------------------------------------------------
# Provenance
# ---------------------------------------------------------------------------


@pytest.mark.no_model
def test_corpus_description_is_derived_from_counts():
    assert corpus_composition(810)["description"] == SYNTHETIC_CORPUS
    assert corpus_composition(810)["real_flows"] == 0

    comp = corpus_composition(810, _samples({"a.pcap": 2, "b.pcap": 1}), ["x.pcap"])
    assert comp["real_flows"] == 3 and comp["real_captures"] == 2
    assert comp["synthetic_flows"] == 810
    assert comp["real_fraction"] == round(3 / 813, 4)
    assert "3 labelled real ESP flows from 2 captures" in comp["description"]
    assert "0.4% of the corpus is real" in comp["description"]
    assert comp["label_sources"] == [SOURCE]
    assert comp["unlabelled_captures_not_used"] == ["x.pcap"]


def test_default_training_is_synthetic_only(model_dir):
    with open(os.path.join(model_dir, "meta.json")) as fh:
        prov = json.load(fh)["provenance"]
    assert prov["corpus"] == SYNTHETIC_CORPUS
    assert prov["corpus_composition"]["real_flows"] == 0
    assert prov["corpus_composition"]["real_captures"] == 0


@pytest.mark.no_model
def test_default_corpus_is_reproducible():
    from cipherguard.ml import features as F
    from cipherguard.ml.synth import build_corpus

    a_flows, a_labels = build_corpus(samples_per_suite=3, seed=11)
    b_flows, b_labels = build_corpus(samples_per_suite=3, seed=11)
    assert a_labels == b_labels
    assert (F.extract_batch(a_flows) == F.extract_batch(b_flows)).all()


@pytest.mark.no_model
def test_train_include_real_records_provenance_and_loco(tmp_path):
    from cipherguard.ml.classifier import SuiteClassifier
    from cipherguard.ml.train import train

    real = tmp_path / "real"
    real.mkdir()
    _capture(real, "gcm.pcap", GCM, packets=300, label=_peer_label(GCM))
    _capture(real, "cbc.pcap", CBC, seed=4, packets=300, label=_peer_label(CBC))
    _capture(real, "unknown.pcap", CBC, seed=5)
    out = str(tmp_path / "model")

    metrics = train(samples_per_suite=6, epochs=2, seed=3, out=out,
                    verbose=False, include_real=str(real))

    rv = metrics["real_validation"]
    assert rv["method"] == "leave-one-capture-out"
    assert rv["captures"] == 2 and rv["flows"] == 2
    assert {f["held_out"] for f in rv["folds"]} == {"cbc.pcap", "gcm.pcap"}
    assert all(f["real_train_flows"] == 1 for f in rv["folds"])

    model = SuiteClassifier.load(out)
    comp = model.corpus
    assert comp["real_flows"] == 2 and comp["real_captures"] == 2
    assert comp["synthetic_flows"] == 6 * 9
    assert comp["unlabelled_captures_not_used"] == ["unknown.pcap"]
    assert comp["description"] != SYNTHETIC_CORPUS
    assert model.provenance["corpus"] == comp["description"]
