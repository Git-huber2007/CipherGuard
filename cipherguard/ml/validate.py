"""Cross-model validation.

Trains on the RFC framing model and evaluates on the independent field model,
then breaks the result down by traffic condition. The per-condition breakdown is
the point: an aggregate number hides which assumption the classifier is actually
leaning on, and a failure confined to one regime is a finding rather than noise.

The comparison to keep in mind while reading the output is that same-model
held-out accuracy is an upper bound. Any gap between it and the cross-model
figure is the portion of performance that came from generator artefacts rather
than from protocol structure.
"""

from __future__ import annotations

from collections import defaultdict

from ..audit.policy import framing_class_of
from ..lab.fieldmodel import build_field_corpus
from ..ml.classifier import SuiteClassifier


def cross_validate(model_dir: str = "models", samples_per_suite: int = 40, seed: int = 5150) -> dict:
    if not SuiteClassifier.is_trained(model_dir):
        raise FileNotFoundError(f"no trained model in {model_dir}/ — run: cipherguard train")
    model = SuiteClassifier.load(model_dir)
    flows, labels, conditions = build_field_corpus(samples_per_suite, seed=seed)

    exact = grouped = 0
    by_condition: dict[str, list[bool]] = defaultdict(list)
    by_class: dict[str, list[bool]] = defaultdict(list)
    confusion: dict[str, dict[str, int]] = defaultdict(lambda: defaultdict(int))
    low_confidence = 0

    for flow, truth, cond in zip(flows, labels, conditions):
        pred = model.predict_one(flow)
        true_cls, _ = framing_class_of(truth)
        pred_cls, _ = framing_class_of(pred.label)
        hit = true_cls == pred_cls

        exact += pred.label == truth
        grouped += hit
        confusion[true_cls or "?"][pred_cls or "?"] += 1
        by_class[true_cls or "?"].append(hit)
        by_condition[f"tfc={cond['tfc']}"].append(hit)
        by_condition[f"mode={cond['mode']}"].append(hit)
        by_condition[f"loss={cond['loss']}"].append(hit)
        if pred.confidence < 0.4:
            low_confidence += 1

    n = len(flows)
    same_model = model.metrics.get("holdout", {}).get("framing_class_accuracy")
    cross = grouped / n

    return {
        "n": n,
        "generator": "field model (independent assumptions)",
        "exact_suite_accuracy": round(exact / n, 4),
        "framing_class_accuracy": round(cross, 4),
        "same_model_framing_accuracy": same_model,
        "transfer_gap": round(same_model - cross, 4) if same_model else None,
        "low_confidence_fraction": round(low_confidence / n, 4),
        "by_condition": {
            k: {"accuracy": round(sum(v) / len(v), 4), "n": len(v)} for k, v in sorted(by_condition.items())
        },
        "by_framing_class": {
            k: {"accuracy": round(sum(v) / len(v), 4), "n": len(v)} for k, v in sorted(by_class.items())
        },
        "confusion": {k: dict(v) for k, v in confusion.items()},
    }


def ablate(model_dir: str = "models", samples_per_suite: int = 30, seed: int = 5150) -> dict:
    """Separate what the arithmetic contributes from what the models contribute.

    A 100% framing-class result is not by itself evidence that the machine
    learning generalises. The plausibility mask is deterministic arithmetic
    derived from RFC 4303, and any conforming IPsec implementation must produce
    the residues it tests for — so the mask alone could plausibly account for
    the entire score, with the RF and CNN contributing nothing.

    Claiming ML performance without checking that would be a straightforward
    misattribution. This ablation runs the same flows with the mask disabled and
    reports both numbers, so the split is visible rather than assumed.
    """
    import numpy as np

    from ..ml import features as F

    model = SuiteClassifier.load(model_dir)
    flows, labels, _ = build_field_corpus(samples_per_suite, seed=seed)

    masked_hits = unmasked_hits = 0
    masked_exact = unmasked_exact = 0

    for flow, truth in zip(flows, labels):
        true_cls, _ = framing_class_of(truth)

        # models only, mask bypassed
        vec = F.extract(flow).reshape(1, -1)
        probs = model._blend(vec)[0]
        raw_label = model.labels[int(np.argmax(probs))]
        raw_cls, _ = framing_class_of(raw_label)
        unmasked_hits += raw_cls == true_cls
        unmasked_exact += raw_label == truth

        # full path
        pred = model.predict_one(flow)
        pred_cls, _ = framing_class_of(pred.label)
        masked_hits += pred_cls == true_cls
        masked_exact += pred.label == truth

    n = len(flows)
    return {
        "n": n,
        "models_only_framing": round(unmasked_hits / n, 4),
        "models_only_exact": round(unmasked_exact / n, 4),
        "with_mask_framing": round(masked_hits / n, 4),
        "with_mask_exact": round(masked_exact / n, 4),
        "mask_contribution": round((masked_hits - unmasked_hits) / n, 4),
    }


def mask_alone(model_dir: str = "models", samples_per_suite: int = 30, seed: int = 5150) -> dict:
    """How far the RFC 4303 constraints get with no learned model at all.

    The ablation reports a delta; this reports the arithmetic's standalone
    result, which is the sharper claim. If the framing constraints alone resolve
    most flows to a single class with no wrong answers, then the learned models
    are handling a residual rather than carrying the system, and the hybrid
    design is a measured fact rather than an argument.
    """

    from ..core.constants import ESP_SUITES
    from .classifier import plausibility

    labels = sorted(ESP_SUITES)
    flows, truths, _ = build_field_corpus(samples_per_suite, seed=seed)

    unique = correct = 0
    survivors_total = 0
    wrong_when_unique = 0

    for flow, truth in zip(flows, truths):
        mask, _excluded, _notes = plausibility(flow, labels)
        surviving = [labels[i] for i in range(len(labels)) if mask[i] > 0]
        survivors_total += len(surviving)

        classes = {framing_class_of(s)[0] for s in surviving}
        if len(classes) == 1:
            unique += 1
            resolved = classes.pop()
            if resolved == framing_class_of(truth)[0]:
                correct += 1
            else:
                wrong_when_unique += 1

    n = len(flows)
    return {
        "n": n,
        "resolved_to_unique_class": round(unique / n, 4),
        "and_correct": round(correct / n, 4),
        "wrong_when_resolved": wrong_when_unique,
        "mean_surviving_suites": round(survivors_total / n, 2),
        "total_suites": len(labels),
    }


def calibration(model_dir: str = "models", samples_per_suite: int = 30, seed: int = 5150, bins: int = 10) -> dict:
    """Expected Calibration Error over framing-class predictions.

    An audit tool that prints "78% confidence" is making a claim, and a finding
    that carries a number nobody checked is worse than one that carries none.
    ECE measures the gap between stated confidence and observed accuracy, so
    the number can be published rather than asserted.
    """
    from .classifier import SuiteClassifier

    model = SuiteClassifier.load(model_dir)
    flows, truths, _ = build_field_corpus(samples_per_suite, seed=seed)

    buckets: list[list[tuple[float, bool]]] = [[] for _ in range(bins)]
    for flow, truth in zip(flows, truths):
        pred = model.predict_one(flow)
        _cls, _members, mass = flow.framing() if flow.predicted_suite else (None, [], 0.0)
        mass = pred.group_confidence
        hit = framing_class_of(pred.label)[0] == framing_class_of(truth)[0]
        idx = min(int(mass * bins), bins - 1)
        buckets[idx].append((mass, hit))

    n = len(flows)
    ece = 0.0
    table = []
    for i, bucket in enumerate(buckets):
        if not bucket:
            continue
        conf = sum(c for c, _ in bucket) / len(bucket)
        acc = sum(1 for _, h in bucket if h) / len(bucket)
        ece += (len(bucket) / n) * abs(acc - conf)
        table.append(
            {
                "range": f"{i / bins:.1f}-{(i + 1) / bins:.1f}",
                "n": len(bucket),
                "mean_confidence": round(conf, 3),
                "accuracy": round(acc, 3),
            }
        )
    return {"n": n, "ece": round(ece, 4), "bins": table}


def format_report(result: dict) -> str:
    lines = [
        "",
        "Cross-model validation",
        f"  Trained on the RFC framing model, evaluated on {result['n']} flows from an",
        "  independent generator with deliberately different traffic assumptions.",
        "",
        f"  Framing-class accuracy   {result['framing_class_accuracy']:.1%}",
        f"  Exact-suite accuracy     {result['exact_suite_accuracy']:.1%}",
    ]
    if result["same_model_framing_accuracy"] is not None:
        lines += [
            f"  Same-model reference     {result['same_model_framing_accuracy']:.1%}",
            f"  Transfer gap             {result['transfer_gap']:+.1%}",
        ]
    lines += ["", "  By traffic condition"]
    for name, stat in result["by_condition"].items():
        lines.append(f"    {name:<22} {stat['accuracy']:.1%}  (n={stat['n']})")
    lines += ["", "  By framing class"]
    for name, stat in result["by_framing_class"].items():
        lines.append(f"    {name:<28} {stat['accuracy']:.1%}  (n={stat['n']})")
    lines += [
        "",
        "  This is cross-model validation, not field validation. It shows the",
        "  classifier keys on protocol structure rather than generator artefacts.",
        "  It does not substitute for a capture from a real gateway.",
        "",
    ]
    return "\n".join(lines)
