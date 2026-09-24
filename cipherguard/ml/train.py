"""Train the ESP suite classifier against the reference testbed corpus."""

from __future__ import annotations

import argparse
import time
from typing import Callable

import numpy as np

from . import features as F
from .classifier import SuiteClassifier, corpus_composition
from .synth import build_corpus

DEFAULT_MODEL_DIR = "models"


def _print_real_corpus(corpus, directory: str) -> None:
    print(f"Real captures from {directory}/: {len(corpus.samples)} labelled flows "
          f"from {len(corpus.captures)} captures")
    for name in corpus.unlabelled:
        print(f"  unlabelled, not used: {name} (no {name}.label.json)")
    for item in corpus.empty:
        print(f"  labelled, not used: {item['capture']} ({item['reason']})")
    for item in corpus.unmatched_entries:
        print(f"  label entry matched no flow: {item['capture']} {item['label']}")
    if corpus.unlabelled_flows:
        print(f"  {len(corpus.unlabelled_flows)} ESP flow(s) in labelled captures "
              "carry no label and were not used")


def holdout_eval(model: SuiteClassifier, seed: int = 909, per_suite: int = 40) -> dict:
    """Evaluate through the complete inference path on flows the model never saw.

    The metrics computed inside `fit` score the raw ensemble on feature vectors.
    That is not what ships: predictions in production also pass the RFC 4303
    plausibility mask, and they are consumed at framing-class granularity. So the
    numbers that matter are measured here, on freshly generated flows, through
    `predict_one` exactly as the pipeline calls it.
    """
    from ..audit.policy import framing_class_of

    flows, labels = build_corpus(samples_per_suite=per_suite, seed=seed)
    exact = grouped = 0
    confusion: dict[str, dict[str, int]] = {}

    for flow, truth in zip(flows, labels):
        pred = model.predict_one(flow)
        exact += pred.label == truth
        true_cls, _ = framing_class_of(truth)
        pred_cls, _ = framing_class_of(pred.label)
        grouped += true_cls == pred_cls
        confusion.setdefault(true_cls or "?", {})
        confusion[true_cls or "?"][pred_cls or "?"] = (
            confusion[true_cls or "?"].get(pred_cls or "?", 0) + 1
        )

    n = len(flows)
    return {
        "n": n,
        "exact_suite_accuracy": round(exact / n, 4),
        "framing_class_accuracy": round(grouped / n, 4),
        "class_confusion": confusion,
    }


class LeakageError(AssertionError):
    """A real flow was about to be scored by a model that trained on it."""


def leave_one_capture_out(
    samples: list,
    fit: Callable[[list], SuiteClassifier],
    verbose: bool = False,
) -> dict:
    """Score every labelled real flow with a model that never saw its capture.

    With a handful of captures, any flow-level split puts flows from the same
    tunnel — same endpoints, same traffic mix, same padding habits — on both
    sides, and the score measures memorisation of the capture rather than
    generalisation to a new one. Holding out whole captures is the only split
    that answers "how will this do on a network we have not seen".

    `fit` receives the real training samples for one fold and returns a fitted
    model; supplying the synthetic corpus is its business. The disjointness
    check below is structural rather than trusted: a fold that would score a
    flow its model trained on raises instead of reporting a number.
    """
    from ..lab.labels import score_flow

    captures = sorted({s.capture for s in samples})
    folds, rows = [], []
    for held_out in captures:
        train_set = [s for s in samples if s.capture != held_out]
        test_set = [s for s in samples if s.capture == held_out]

        trained_ids = {id(s.flow) for s in train_set}
        leaked = [s for s in test_set if id(s.flow) in trained_ids]
        if leaked:
            raise LeakageError(
                f"fold {held_out}: {len(leaked)} flow(s) in both train and test"
            )

        if verbose:
            print(f"  fold: hold out {held_out} "
                  f"({len(test_set)} test, {len(train_set)} real train flows)")
        model = fit(train_set)

        fold_rows = []
        for s in test_set:
            row = score_flow(model, s.flow, s.suite)
            row["capture"] = s.capture
            row["label_source"] = s.source
            fold_rows.append(row)
        hits = sum(1 for r in fold_rows if r["hit"])
        folds.append({
            "held_out": held_out,
            "test_flows": len(test_set),
            "real_train_flows": len(train_set),
            "real_train_captures": len({s.capture for s in train_set}),
            "framing_class_hits": hits,
        })
        rows += fold_rows

    n = len(rows)
    hits = sum(1 for r in rows if r["hit"])
    return {
        "method": "leave-one-capture-out",
        "captures": len(captures),
        "flows": n,
        "framing_class_hits": hits,
        "framing_class_accuracy": round(hits / n, 4) if n else None,
        "exact_suite_matches": sum(1 for r in rows if r["exact_suite_match"]),
        "folds": folds,
        "misses": [r for r in rows if not r["hit"]],
        "note": (
            "Each real flow is scored by a model trained on the synthetic corpus "
            "plus real flows from other captures only. With few captures this "
            "figure has wide uncertainty; read it as a count, not a rate."
        ),
    }


def train(
    samples_per_suite: int = 90,
    epochs: int = 60,
    seed: int = 42,
    out: str = DEFAULT_MODEL_DIR,
    verbose: bool = True,
    include_real: str | None = None,
    min_packets: int = 8,
) -> dict:
    """Train and save the model.

    Without `include_real` the corpus is synthetic only and fully determined by
    `seed`, which is the default and must stay reproducible. Real captures are
    strictly opt-in.
    """
    if verbose:
        print(f"Building reference corpus ({samples_per_suite} flows per suite)")
    flows, labels = build_corpus(samples_per_suite=samples_per_suite, seed=seed)

    t0 = time.time()
    X = F.extract_batch(flows)
    if verbose:
        print(f"Extracted {X.shape[0]}x{X.shape[1]} features in {time.time() - t0:.1f}s")

    corpus = None
    if include_real:
        from ..lab.labels import collect

        corpus = collect(include_real, min_packets=min_packets)
        if verbose:
            _print_real_corpus(corpus, include_real)

    def fit(real_train: list) -> SuiteClassifier:
        m = SuiteClassifier()
        if real_train:
            Xr = F.extract_batch([s.flow for s in real_train])
            X_all = np.vstack([X, Xr])
            y_all = labels + [s.suite for s in real_train]
        else:
            X_all, y_all = X, labels
        m.fit(X_all, y_all, epochs=epochs, seed=seed, verbose=False)
        return m

    real_validation = None
    if corpus is not None and corpus.samples:
        if verbose:
            print(f"Leave-one-capture-out over {len(corpus.captures)} captures")
        real_validation = leave_one_capture_out(corpus.samples, fit, verbose=verbose)

    real_train = corpus.samples if corpus else []
    if real_train:
        model = fit(real_train)
        metrics = model.metrics
    else:
        model = SuiteClassifier()
        metrics = model.fit(X, labels, epochs=epochs, seed=seed, verbose=verbose)

    if verbose:
        print("Evaluating the full inference path on held-out flows")
    metrics["holdout"] = holdout_eval(model, seed=seed + 867)
    if real_validation is not None:
        metrics["real_validation"] = real_validation
    model.metrics = metrics
    model.corpus = corpus_composition(
        len(flows), real_train, corpus.unlabelled if corpus else None
    )
    if corpus is not None:
        model.corpus["real_capture_dir"] = include_real
        model.corpus["labelled_captures_without_usable_flows"] = corpus.empty
    model.save(out)

    if verbose:
        h = metrics["holdout"]
        print(f"\n  Random Forest, raw ensemble input   {metrics['rf_accuracy']:.1%}")
        print(f"  1D-CNN, raw ensemble input          {metrics['cnn_accuracy']:.1%}")
        print(f"  Ensemble, no plausibility mask      {metrics['ensemble_accuracy']:.1%}")
        print(f"\n  Held out, exact suite               {h['exact_suite_accuracy']:.1%}")
        print(f"  Held out, framing class             {h['framing_class_accuracy']:.1%}")
        rv = metrics.get("real_validation")
        if rv:
            print(f"\n  Real flows, leave-one-capture-out   {rv['framing_class_hits']}/"
                  f"{rv['flows']} framing class over {rv['captures']} captures")
        print(f"\n  Corpus: {model.corpus['description']}")
        print(
            "\n  Exact-suite accuracy is capped well below 100% by design: suites\n"
            "  sharing IV, ICV and block size are not separable from passive\n"
            "  observation at all. Framing class is the number that governs the\n"
            "  audit verdict, and it is what the findings are phrased against."
        )
        print(f"\nSaved to {out}/")
    return metrics


def main() -> None:
    ap = argparse.ArgumentParser(description="Train the ESP inference model")
    ap.add_argument("--samples", type=int, default=90, help="flows per suite")
    ap.add_argument("--epochs", type=int, default=60, help="CNN training epochs")
    ap.add_argument("--seed", type=int, default=42)
    ap.add_argument("--out", default=DEFAULT_MODEL_DIR)
    ap.add_argument("--include-real", metavar="DIR",
                    help="add labelled real captures (<capture>.label.json) from DIR")
    args = ap.parse_args()
    train(args.samples, args.epochs, args.seed, args.out, include_real=args.include_real)


if __name__ == "__main__":
    main()
