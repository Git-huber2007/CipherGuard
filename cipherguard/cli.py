"""CipherGuard command-line interface."""

from __future__ import annotations

import argparse
import json
import os
import sys
from datetime import datetime

from .audit.engine import rule_catalogue
from .audit.policy import framing_class_of
from .audit.policy_config import PolicyError
from .ml.classifier import ModelSchemaError
from .core.models import Assessment, Severity
from .intel.baseline import DEFAULT_RETAIN_DAYS, DEFAULT_RETAIN_PER_PEER
from .pipeline import analyze, throughput_estimate
from .remediation.synth import PLATFORM_NAMES, detect_platforms, synthesize

# ANSI colours, disabled when not writing to a terminal
_TTY = sys.stdout.isatty()


def _c(code: str, text: str) -> str:
    return f"\033[{code}m{text}\033[0m" if _TTY else text


SEV_COLOR = {
    Severity.CRITICAL: "1;31",
    Severity.HIGH: "31",
    Severity.MEDIUM: "33",
    Severity.LOW: "36",
    Severity.INFO: "90",
}


def _bar(score: int, width: int = 28) -> str:
    filled = round(score / 100 * width)
    return "[" + "#" * filled + "." * (width - filled) + "]"


def print_report(a: Assessment, verbose: bool = False) -> None:
    st = a.stats
    print()
    print(_c("1", f"CipherGuard assessment - {a.capture}"))
    print(f"  {st['packets_read']} packets  |  {st['ike_sessions']} IKE sessions  |  "
          f"{st['esp_flows_assessed']} ESP SAs  |  {st['analysis_seconds']}s")
    print()

    score = a.score()
    colour = "32" if score >= 75 else "33" if score >= 50 else "1;31"
    print(f"  Posture  {_c(colour, f'{score:3d}/100  grade {a.grade()}')}  {_bar(score)}")

    counts = a.counts()
    summary = "  ".join(
        _c(SEV_COLOR[s], f"{counts[s.value]} {s.value}")
        for s in Severity
        if counts[s.value]
    )
    print(f"           {summary or 'no findings'}")
    print()

    if a.sessions:
        print(_c("1", "  Negotiated IKE security associations (parsed from the wire)"))
        for s in a.sessions:
            prop = s.negotiated("IKE")
            algs = ", ".join(t.label() for t in prop.transforms) if prop else "not observed"
            print(f"    {s.peer_a} <-> {s.peer_b}   {s.version}   [{s.vendor_family()}]")
            print(f"      {algs}")
        print()

    if a.flows:
        print(_c("1", "  ESP tunnels (inferred - payload never decrypted)"))
        for f in a.flows:
            print(f"    {f.src} -> {f.dst}  SPI 0x{f.spi:08x}  {f.packets} packets")

            # Report the framing class, not an arbitrary member of it. Printing
            # `predicted_suite` names one suite out of a set the wire cannot
            # distinguish, at its exact-suite probability — so a correctly
            # identified AES-GCM link displays as "ChaCha20-Poly1305, 30%" and
            # reads as a wrong answer. The class and its confidence are the
            # claim actually supported by the evidence.
            cls_name, spec = framing_class_of(f.predicted_suite or "")
            if spec:
                members = spec["members"]
                group_conf = sum(p for name, p in f.ranked if name in members)
                print(f"      {cls_name}  ({group_conf:.0%} confidence)")
                if len(members) > 1:
                    print(_c("90", f"      {' or '.join(members)}"))
                    print(_c("90", "      framing-identical; not separable passively"))
                elif verbose:
                    print(_c("90", f"      {members[0]}"))
            else:
                print(f"      {f.predicted_suite or 'unresolved'}  "
                      f"({f.confidence:.0%} confidence)")
        print()

    if a.findings:
        print(_c("1", "  Findings"))
        for f in a.findings:
            tag = _c("90", " [inferred]") if f.inferred else ""
            label = _c(SEV_COLOR[f.severity], f"{f.severity.value.upper():>8}")
            print(f"    {label}  {f.rule_id}  {f.title}{tag}")
            print(f"              {f.subject}")
            if verbose:
                for line in _wrap(f.detail, 74):
                    print(f"              {_c('90', line)}")
                print(f"              {_c('90', 'Ref: ' + f.reference)}")
                for line in _wrap("Fix: " + f.remediation, 74):
                    print(f"              {_c('36', line)}")
                print()
    else:
        print(_c("32", "  No findings. Every observed SA meets the configured baseline."))
    print()


def _wrap(text: str, width: int) -> list[str]:
    words, lines, cur = text.split(), [], ""
    for w in words:
        if len(cur) + len(w) + 1 > width:
            lines.append(cur)
            cur = w
        else:
            cur = f"{cur} {w}".strip()
    if cur:
        lines.append(cur)
    return lines


# ---------------------------------------------------------------------------
# Subcommands
# ---------------------------------------------------------------------------


def _apply_policy(args) -> dict | None:
    if not getattr(args, "policy", None):
        return None
    from .audit.policy_config import load_and_apply

    record = load_and_apply(args.policy, replace=getattr(args, "policy_replace", False))
    print(_c("90", f"  policy overlay: {record['name']} ({record['mode']})"))
    return record


def cmd_analyze(args: argparse.Namespace) -> int:
    from .core.audit_log import AuditLog

    _apply_policy(args)
    disabled = set(args.disable.split(",")) if args.disable else None
    a = analyze(args.capture, model_dir=args.models, min_esp_packets=args.min_packets,
                disabled_rules=disabled)
    AuditLog(args.audit_log or None).assessment(a, args.capture, source="cli")

    if args.json:
        payload = a.to_dict()
        payload["throughput"] = throughput_estimate(a)
        text = json.dumps(payload, indent=2)
        if args.out:
            with open(args.out, "w") as fh:
                fh.write(text)
            print(f"Wrote {args.out}")
        else:
            print(text)
    else:
        print_report(a, verbose=args.verbose)
        if args.out:
            with open(args.out, "w") as fh:
                json.dump(a.to_dict(), fh, indent=2)
            print(f"  Full report written to {args.out}\n")

    if args.fail_under and a.score() < args.fail_under:
        print(_c("1;31", f"  Score {a.score()} is below the required {args.fail_under}."))
        return 2
    return 0




def cmd_watch(args: argparse.Namespace) -> int:
    """Record an assessment against the persistent baseline and report drift."""
    from .intel.baseline import BaselineStore

    a = analyze(args.capture, model_dir=args.models)
    with BaselineStore(args.db) as store:
        drifts = store.record(a)
        summary = store.summary()

    print()
    print(_c("1", f"Baseline updated from {a.capture}"))
    print(f"  {summary['links']} links tracked over {summary['observations']} observations")
    print(f"  {summary['below_112_bits']} below the 112-bit floor  |  "
          f"{summary['quantum_exposed']} quantum-exposed  |  "
          f"{summary['degraded']} currently degraded")
    print()

    downgrades = [d for d in drifts if d.kind == "downgrade"]
    if downgrades:
        print(_c("1;31", "  Cryptographic downgrade detected"))
        for d in downgrades:
            print(f"    {d.peer_key}")
            print(f"      was {d.previous_bits} bits ({', '.join(d.previous_transforms)})")
            print(f"      now {d.current_bits} bits ({', '.join(d.current_transforms)})")
            print(_c("90", f"      baseline established {d.baseline_seen_at}"))
        print()
        print(_c("90", "  A single capture cannot see this. Only comparison against"))
        print(_c("90", "  prior observations of the same peer pair reveals it."))
        print()
    else:
        for d in drifts:
            verb = "new link" if d.kind == "new" else "improved"
            print(f"  {verb}: {d.peer_key} at {d.current_bits} bits")
        print()

    if args.fleet:
        print(_c("1", "  Fleet triage queue (weakest first)"))
        for row in BaselineStore(args.db).fleet():
            flag = _c("1;31", " DEGRADED") if row["degraded"] else ""
            qs = "PQ-safe" if row["current_quantum"] >= 128 else "PQ-exposed"
            print(f"    {row['current_bits']:>4} bits  {qs:<11} {row['peer_key']}{flag}")
        print()

    return 3 if downgrades else 0


def cmd_roadmap(args: argparse.Namespace) -> int:
    """Rank links by harvest-now-decrypt-later exposure."""
    from .intel.pqc import roadmap

    a = analyze(args.capture, model_dir=args.models)
    plan = roadmap(a, data_class=args.data_class,
                   migration_years=args.migration_years,
                   crqc_years=args.crqc_years)

    if args.json:
        print(json.dumps(plan, indent=2))
        return 0

    assume, summary = plan["assumptions"], plan["summary"]
    print()
    print(_c("1", "Post-quantum migration roadmap"))
    print(f"  {summary['quantum_exposed']} of {summary['links_assessed']} links are "
          f"quantum-exposed, carrying "
          f"{summary['total_bytes_harvestable'] / 1e6:.1f} MB of observed traffic")
    print()
    print(f"  Data class '{assume['data_class']}' stays sensitive for "
          f"{assume['secrecy_lifetime_years']:.0f} years; migration takes "
          f"{assume['migration_years']:.0f}; CRQC assumed in {assume['crqc_years']:.0f}.")
    gap = assume["mosca_gap_years"]
    if assume["already_late"]:
        print(_c("1;31", f"  Mosca gap +{gap} years: data recorded today will still be "
                         "sensitive when it becomes decryptable."))
    else:
        print(_c("32", f"  Mosca gap {gap} years of margin remaining."))
    print()

    for link in plan["links"]:
        mark = _c("32", "safe") if link["quantum_safe"] else _c("31", f"idx {link['exposure_index']}")
        print(f"  {link['priority']}. [{mark}] {link['peer']}")
        print(f"      {link['classical_bits']} classical / {link['quantum_bits']} quantum bits"
              f"  ·  {link['bytes_observed'] / 1e6:.1f} MB observed"
              f"  ·  {link['harvest_rate_mbps']} Mbps")
        for line in _wrap(link["rationale"], 70):
            print(_c("90", f"      {line}"))
    print()

    for phase in plan["phases"]:
        print(_c("1", f"  Phase {phase['phase']} — {phase['window']}"))
        for line in _wrap(phase["action"], 72):
            print(f"    {line}")
        print(_c("36", f"    Target: {phase['target']}"))
        for peer in phase["links"]:
            print(_c("90", f"      · {peer}"))
        print()
    return 0


def cmd_cbom(args: argparse.Namespace) -> int:
    """Emit a CycloneDX Cryptographic Bill of Materials."""
    from .export.cbom import build_cbom

    a = analyze(args.capture, model_dir=args.models)
    doc = build_cbom(a)
    text = json.dumps(doc, indent=2)
    if args.out:
        with open(args.out, "w") as fh:
            fh.write(text)
        observed = sum(
            1 for c in doc["components"]
            if any(p["name"] == "cipherguard:provenance" and p["value"] == "observed"
                   for p in c.get("properties", []))
        )
        inferred = len(doc["components"]) - observed
        print(f"Wrote {args.out}")
        print(f"  CycloneDX {doc['specVersion']} · {len(doc['components'])} cryptographic "
              f"assets ({observed} observed, {inferred} inferred)")
        print(f"  {len(doc['vulnerabilities'])} vulnerabilities recorded")
    else:
        print(text)
    return 0


def cmd_train(args: argparse.Namespace) -> int:
    from .lab.labels import LabelError
    from .ml.train import train

    try:
        train(args.samples, args.epochs, args.seed, args.models,
              include_real=args.include_real, min_packets=args.min_packets)
    except LabelError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 5
    return 0


def _load_model_or_explain(model_dir: str):
    from .ml.classifier import SuiteClassifier

    if not SuiteClassifier.is_trained(model_dir):
        print(f"error: no trained model in {model_dir}/. Run: cipherguard train",
              file=sys.stderr)
        return None
    return SuiteClassifier.load(model_dir)


def _print_label_result(r: dict) -> None:
    """One capture's ESP label comparison, misses explained in full."""
    if not r["labelled"]:
        print(f"  [{_c('33', 'UNLABELLED')}] {r['capture']}")
        print(_c("90", f"         no {os.path.basename(r['label_path'])}; ESP ground "
                       "truth must come from the endpoint's own configuration"))
        return

    mark = _c("32", "PASS") if r["passed"] else _c("1;31", "FAIL")
    print(f"  [{mark}] {r['capture']}  {r['hits']}/{len(r['results'])} flows "
          "correct at framing-class level")
    if r["label_source"]:
        print(_c("90", f"         label source: {r['label_source']}"))

    for row in r["results"]:
        tag = _c("32", "hit ") if row["hit"] else _c("1;31", "MISS")
        print(f"    {tag} {row['flow']}  ({row['packets']} packets)")
        print(f"         label     {row['label_class']}  [{row['label_suite']}]")
        print(f"         inferred  {row['predicted_class']}  "
              f"({row['class_confidence']:.0%} confidence)")
        if row["label_source"] != r["label_source"]:
            print(_c("90", f"         label source: {row['label_source']}"))
        miss = row.get("miss")
        if miss:
            for line in _wrap("Diagnosis: " + miss["diagnosis"], 66):
                print(_c("33", f"         {line}"))
            print(_c("90", f"         labelled class held "
                           f"{miss['truth_class_probability']:.0%} of the probability"))
            if miss["all_exclusions"]:
                print(_c("90", "         plausibility exclusions:"))
                for ex in miss["all_exclusions"]:
                    flag = " <- labelled class" if ex in miss["truth_excluded"] else ""
                    print(_c("90", f"           {ex['suite']}: {ex['reason']}{flag}"))
            else:
                print(_c("90", "         plausibility exclusions: none"))

    for u in r.get("unmatched_entries", []):
        print(_c("33", f"    label entry {u['label']} ({u['suite']}) matched no flow"))
    for s in r.get("too_short", []):
        print(_c("33", f"    {s['flow']} is labelled but has only {s['packets']} "
                       f"packets (< {r['min_packets']}); not scored"))
    for u in r.get("unlabelled_flows", []):
        print(_c("90", f"    unlabelled flow {u['flow']} ({u['packets']} packets); "
                       "not scored"))


def cmd_label_check(args: argparse.Namespace) -> int:
    """Compare ESP inference against a user-supplied ground-truth label."""
    from .lab.labels import LabelError, check_capture

    if not os.path.exists(args.capture):
        raise FileNotFoundError(args.capture)
    model = _load_model_or_explain(args.models)
    if model is None:
        return 1
    try:
        result = check_capture(args.capture, model, min_packets=args.min_packets)
    except LabelError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 5

    if args.json:
        print(json.dumps(result, indent=2))
    else:
        print()
        print(_c("1", "ESP inference against labelled ground truth"))
        print(_c("90", f"  model corpus: {model.corpus['description']}"))
        print()
        _print_label_result(result)
        print()
    if not result["labelled"]:
        return 1
    return 0 if result["passed"] else 1


def _prune_evidence(
    directory: str, keep: int, max_bytes: int, protect: str | None = None
) -> tuple[int, int]:
    """Enforce the evidence retention policy, oldest first.

    A sensor is a long-running process writing one capture per window. Without a
    retention policy that is unbounded growth on the sensor's own disk — at
    300-second windows a 50 Mbps link produces about 540 GB a day, so the host
    fills in hours and the monitoring dies. Retention is therefore part of the
    feature, not an operational afterthought.

    Both ceilings apply: a count keeps the recent history predictable, and a
    byte cap is what actually protects the disk, because window size varies with
    link load and a count alone cannot bound it.

    `protect` is the capture behind the most recent assessment, and is never
    removed. Without it a single window larger than `max_bytes` deleted itself
    the moment it had been assessed, so the latest finding had no evidence.
    The ceiling is then exceeded by that one window, which `--max-window-mb`
    bounds.
    """
    try:
        files = sorted(
            (os.path.join(directory, n) for n in os.listdir(directory)
             if n.startswith("window-") and n.endswith(".pcap")),
            key=os.path.getmtime,
        )
    except OSError:
        return 0, 0

    guarded = os.path.normcase(os.path.abspath(protect)) if protect else None

    def drop_oldest() -> bool:
        for i, f in enumerate(files):
            if os.path.normcase(os.path.abspath(f)) == guarded:
                continue
            try:
                os.remove(f)
            except OSError:
                return False
            files.pop(i)
            return True
        return False

    removed = 0
    while len(files) > keep and drop_oldest():
        removed += 1

    def total() -> int:
        return sum(os.path.getsize(f) for f in files if os.path.exists(f))

    while files and max_bytes and total() > max_bytes and drop_oldest():
        removed += 1

    return removed, total()


def cmd_sensor(args: argparse.Namespace) -> int:
    """Continuous passive monitoring: capture, assess, baseline, repeat.

    This is the deployment mode the project describes. Everything else in the
    CLI operates on a file somebody already captured by hand, which is a batch
    job rather than continuous assurance.
    """
    import signal

    from .capture.live import CaptureUnavailable, LiveCapture, available
    from .core.audit_log import AuditLog
    from .core.health import write_sensor_state
    from .intel.baseline import BaselineStore

    ok, why = available()
    if not ok:
        print(f"error: {why}", file=sys.stderr)
        return 1

    os.makedirs(args.out, exist_ok=True)
    log = AuditLog(args.audit_log or None, actor="sensor",
                   max_bytes=args.audit_max_mb * (1 << 20), backups=args.audit_backups)
    running = {"go": True}

    def stop(_sig, _frm):
        running["go"] = False
        print("\n  stopping after this window…")

    signal.signal(signal.SIGINT, stop)
    signal.signal(signal.SIGTERM, stop)

    print(f"Sensor on {args.interface}  ·  {args.window}s windows  ·  output {args.out}/")
    print("  receive-only socket; Ctrl-C to stop\n")

    window = 0
    exit_code = 0
    while running["go"] and (not args.windows or window < args.windows):
        window += 1
        stamp = datetime.now().strftime("%Y%m%dT%H%M%S")
        pcap_path = os.path.join(args.out, f"window-{stamp}.pcap")

        try:
            with LiveCapture(args.interface, snaplen=args.snaplen) as cap:
                for _ in cap.packets(
                    max_seconds=args.window,
                    max_bytes=args.max_window_mb * (1 << 20),
                    pcap_path=pcap_path,
                ):
                    pass
                stats = cap.stats.to_dict()
                truncated = cap.truncated
        except CaptureUnavailable as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 1

        if stats["packets"] == 0:
            print(f"  [{stamp}] no IPsec traffic observed")
            os.path.exists(pcap_path) and os.remove(pcap_path)
            # A quiet link is a completed window, not a stalled sensor.
            write_sensor_state(args.out, window=window, window_seconds=args.window,
                               packets=0, evidence=None)
            continue

        # A capture that silently lost packets yields a misleading assessment,
        # not merely a weaker one, so the loss is surfaced next to the result.
        loss_note = ""
        if truncated:
            loss_note += _c("33", f"  [window capped at {args.max_window_mb} MB]")
        if stats["dropped"]:
            pct = stats["dropped"] / max(stats["packets"] + stats["dropped"], 1) * 100
            loss_note = _c("1;31", f"  [kernel dropped {stats['dropped']} ({pct:.1f}%)]")

        assessment = analyze(pcap_path, model_dir=args.models)
        log.assessment(assessment, pcap_path, source="sensor")

        drifts = []
        if args.db:
            with BaselineStore(args.db, retain_per_peer=args.retain_observations,
                               retain_days=args.retain_days) as store:
                drifts = store.record(assessment)

        # Evidence handling. The assessment is already complete at this point,
        # so keeping the capture is a custody decision rather than a functional
        # need — and on a busy link it is the expensive one.
        if args.no_evidence:
            os.path.exists(pcap_path) and os.remove(pcap_path)
            retained = 0
        else:
            _removed, retained = _prune_evidence(
                args.out, args.retain, args.max_disk_mb * (1 << 20), protect=pcap_path
            )

        write_sensor_state(
            args.out, window=window, window_seconds=args.window,
            packets=stats["packets"], score=assessment.score(),
            grade=assessment.grade(),
            evidence=None if args.no_evidence else os.path.basename(pcap_path),
        )

        counts = assessment.counts()
        disk_note = f"  {retained / (1 << 20):.0f}MB kept" if retained else ""
        print(f"  [{stamp}] {stats['packets']} pkts  score {assessment.score()}/100 "
              f"({assessment.grade()})  "
              f"{counts['critical']}C {counts['high']}H  "
              f"{len(assessment.sessions)} SA{disk_note}{loss_note}")

        for d in [x for x in drifts if x.kind == "downgrade"]:
            print(_c("1;31", f"    DOWNGRADE {d.peer_key}: "
                             f"{d.previous_bits} -> {d.current_bits} bits"))
            exit_code = 3

        if args.fail_under and assessment.score() < args.fail_under:
            print(_c("1;31", f"    score below {args.fail_under}"))
            exit_code = max(exit_code, 2)

    return exit_code


def cmd_healthcheck(args: argparse.Namespace) -> int:
    """Exit 0 / 1 / 2 for a healthy / degraded / failed sensor deployment."""
    from .core import health

    checks = health.run_checks(
        model_dir=args.models,
        baseline_db=args.db or None,
        evidence_dir=args.out,
        max_disk_bytes=args.max_disk_mb * (1 << 20),
        max_window_bytes=args.max_window_mb * (1 << 20),
        no_evidence=args.no_evidence,
        audit_log=args.audit_log or None,
        audit_max_bytes=args.audit_max_mb * (1 << 20),
        audit_backups=args.audit_backups,
        stale_after=args.stale_after,
    )
    status = health.overall(checks)

    if args.json:
        print(json.dumps({"status": health.STATUS_NAMES[status], "exit_code": status,
                          "checks": [c.to_dict() for c in checks]}, indent=2))
        return status

    tags = {health.OK: _c("32", " ok "), health.DEGRADED: _c("33", "WARN"),
            health.FAILED: _c("1;31", "FAIL")}
    print()
    print(_c("1", "CipherGuard sensor healthcheck"))
    for c in checks:
        print(f"  [{tags[c.status]}] {c.name:<12} {c.detail}")
    print(f"\n  {health.STATUS_NAMES[status]} (exit {status})\n")
    return status


def cmd_verify_real(args: argparse.Namespace) -> int:
    """Validate the dissector against real captures from a public corpus."""
    from .lab.labels import LABEL_SUFFIX, find_captures
    from .lab.realworld import EXPECTATIONS, SOURCE, check_all

    result = check_all(args.dir)
    labelled = [
        n for n in find_captures(args.dir)
        if os.path.exists(os.path.join(args.dir, n + LABEL_SUFFIX))
    ]
    if not result["available"] and not labelled:
        print(f"No real captures in {args.dir}/. Fetch them with:")
        print("    ./scripts/fetch-real-captures.sh")
        print(f"or add your own with a <capture>{LABEL_SUFFIX} sidecar.")
        return 1

    print()
    print(_c("1", "Validation against real-world captures"))
    ike_ok = _verify_real_ike(args, result, EXPECTATIONS, SOURCE)
    esp_ok = _verify_real_esp(args, labelled)

    known = {e.filename for e in EXPECTATIONS}
    uncovered = [n for n in find_captures(args.dir)
                 if n not in known and n not in labelled]
    if uncovered:
        print(_c("33", f"  {len(uncovered)} capture(s) in {args.dir}/ are unlabelled and "
                       "validate nothing:"))
        for name in uncovered:
            print(_c("33", f"    {name}  (add {name}{LABEL_SUFFIX} to use it)"))
        print()
    return 0 if ike_ok and esp_ok else 1


def _verify_real_esp(args: argparse.Namespace, labelled: list[str]) -> bool:
    """ESP inference against user-labelled captures, reported on its own."""
    from .lab.labels import check_directory

    print(_c("1", "  ESP inference (ground truth: endpoint configuration, via labels)"))
    if not labelled:
        print(_c("90", "    No labelled captures. The ESP model has NOT been validated "
                       "against real traffic."))
        print()
        return True

    model = _load_model_or_explain(args.models)
    if model is None:
        return False
    esp = check_directory(args.dir, model)
    print(_c("90", f"    model corpus: {model.corpus['description']}"))
    if model.corpus.get("real_flows"):
        print(_c("33", "    This model trained on labelled real flows, possibly these "
                       "ones; for an unbiased figure use the leave-one-capture-out "
                       "result recorded by `train --include-real`."))
    print()
    for r in esp["captures"]:
        _print_label_result(r)
        print()
    for err in esp["label_errors"]:
        print(_c("1;31", f"  [LABEL ERROR] {err['capture']}: {err['error']}"))
        print()
    print(f"  ESP: {esp['hits']}/{esp['flows']} flows correct at framing-class level "
          f"across {esp['labelled']} labelled capture(s)")
    print()
    return esp["passed"]


def _verify_real_ike(args: argparse.Namespace, result: dict, EXPECTATIONS, SOURCE) -> bool:
    """The IKE dissector against the public Wireshark corpus."""
    print(_c("1", "  IKE dissector (ground truth: upstream filenames)"))
    if not result["available"]:
        print(_c("90", "    No public IKE captures present. Fetch with "
                       "./scripts/fetch-real-captures.sh"))
        print()
        return True
    print(f"  Source: {SOURCE}")
    print(f"  Ground truth is the upstream filename, not anything written here.")
    print()

    by_name = {e.filename: e for e in EXPECTATIONS}
    for r in result["results"]:
        mark = _c("32", "PASS") if r["passed"] else _c("1;31", "FAIL")
        print(f"  [{mark}] {r['capture']}")
        integ = ", ".join(r["integrity"]) if r["integrity"] else "none (AEAD)"
        print(f"         {r['version']} · {r['encryption']} · integ {integ} "
              f"· DH group {r['dh_group']}")
        print(_c("90", f"         {r['packets']} packets, {r['ike_messages']} IKE "
                       f"messages, {len(r['vendor_ids'])} vendor IDs"))
        if args.verbose:
            for line in _wrap(by_name[r["capture"]].notes, 66):
                print(_c("90", f"         {line}"))
        for problem in r["problems"]:
            print(_c("1;31", f"         {problem}"))
        print()

    print(f"  IKE: {result['passed']}/{result['available']} validated")
    if result["missing"]:
        print(_c("90", f"  {len(result['missing'])} not downloaded: "
                       + ", ".join(result["missing"])))
    print()
    return result["passed"] == result["available"]


def cmd_bench(args: argparse.Namespace) -> int:
    """Generate a large capture and measure reader and pipeline throughput."""
    from .lab.bench import run

    print(f"Generating a ~{args.packets:,}-packet capture and timing "
          f"{args.repeat} interleaved runs of each path...")
    result = run(packets=args.packets, model_dir=args.models, repeat=args.repeat,
                 keep=args.keep)
    if args.json:
        print(json.dumps(result, indent=2))
        return 0

    cap, rd, pl = result["capture"], result["reader"], result["pipeline"]
    print()
    print(_c("1", "CipherGuard throughput benchmark"))
    print(f"  capture   {cap['packets']:,} packets, {cap['bytes'] / 1e6:.1f} MB, "
          f"{cap['links']} gateway pairs (generated in {cap['generate_seconds']}s)")
    print(f"  host      Python {result['host']['python']} on {result['host']['platform']}")
    print()
    def spread(r: dict) -> str:
        lo, hi = r.get("range") or (None, None)
        return f"range {lo:,.0f}-{hi:,.0f}" if lo else ""

    print(f"  reader    {rd['packets_per_second']:>10,.0f} packets/sec   "
          + _c("90", spread(rd)))
    if pl["packets_per_second"] is None:
        print("  pipeline  not measurable: capture below the minimum size")
    else:
        print(f"  pipeline  {pl['packets_per_second']:>10,.0f} packets/sec   "
              + _c("90", spread(pl)))
    load = (f"{pl['model_load_seconds']}s, excluded from the rate above"
            if pl["model_loaded"] else "no trained model found; inference skipped")
    print(_c("90", f"  model load {load}"))
    print()
    print(_c("90", f"  Median of {result['repeat']} interleaved runs after a warm-up, "
                   "single-threaded pure-Python path. Rates depend on the host; "
                   "compare runs on the same machine."))
    print()
    return 0


def cmd_export_demo(args: argparse.Namespace) -> int:
    """Render a static build of the dashboard for GitHub Pages."""
    from .export.static_site import export

    manifest = export(capture_dir=args.captures, out_dir=args.out,
                      model_dir=args.models)
    print()
    for entry in manifest["captures"]:
        print(f"    {entry['name']:<28} {entry['score']:>3}/100  grade {entry['grade']}")
    print()
    return 0


def cmd_validate(args: argparse.Namespace) -> int:
    """Cross-model validation plus the mask/model ablation."""
    from .ml.validate import ablate, cross_validate, format_report

    from .ml.validate import calibration, mask_alone

    result = cross_validate(model_dir=args.models, samples_per_suite=args.samples)
    if args.json:
        result["ablation"] = ablate(args.models, args.samples)
        result["mask_alone"] = mask_alone(args.models, args.samples)
        result["calibration"] = calibration(args.models, args.samples)
        print(json.dumps(result, indent=2))
        return 0

    print(format_report(result))
    abl = ablate(args.models, args.samples)
    print("  Ablation: what carries the result")
    print(f"    Learned models alone      {abl['models_only_framing']:.1%} framing class")
    print(f"    With RFC 4303 mask        {abl['with_mask_framing']:.1%}")
    print(f"    Arithmetic contributes    {abl['mask_contribution']:+.1%}")
    print()
    for line in _wrap(
        "The learned models lose accuracy on traffic they were not generated "
        "for, which is exactly what a same-model evaluation cannot reveal. The "
        "deterministic framing constraints do not, because they are protocol "
        "arithmetic rather than a fitted pattern. That split is the argument "
        "for the hybrid design.", 72):
        print(f"    {_c('90', line)}")
    print()

    ma = mask_alone(args.models, args.samples)
    print("  RFC 4303 constraints with no learned model at all")
    print(f"    Resolved to a single framing class  {ma['resolved_to_unique_class']:.1%}")
    print(f"    ...and that class was correct       {ma['and_correct']:.1%}")
    print(f"    Wrong whenever it resolved          {ma['wrong_when_resolved']}")
    print(f"    Mean surviving suites               {ma['mean_surviving_suites']} of "
          f"{ma['total_suites']}")
    print()
    for line in _wrap(
        "The arithmetic never produces a wrong answer; it either resolves a "
        "flow or declines to. The models handle the residual and rank within a "
        "class, which is a narrower job than the headline accuracy implies.", 72):
        print(f"    {_c('90', line)}")
    print()

    cal = calibration(args.models, args.samples)
    print(f"  Confidence calibration (framing class), ECE {cal['ece']:.3f}")
    print(f"    {'confidence':<14}{'n':>6}  {'stated':>8}  {'observed':>9}")
    for b in cal["bins"]:
        print(f"    {b['range']:<14}{b['n']:>6}  {b['mean_confidence']:>8.3f}  "
              f"{b['accuracy']:>9.3f}")
    print()
    for line in _wrap(
        "A finding that carries a number nobody checked is worse than one that "
        "carries none. Stated confidence tracks observed accuracy closely, so "
        "the figures in findings can be relied on.", 72):
        print(f"    {_c('90', line)}")
    print()
    return 0


def cmd_lab(args: argparse.Namespace) -> int:
    from .lab.pcapgen import SCENARIOS, generate_all

    if args.list:
        for name, (_fn, desc) in SCENARIOS.items():
            print(f"  {name:14} {desc}")
        return 0
    written = generate_all(args.out)
    for path in written:
        size = os.path.getsize(path) / 1024
        print(f"  {path}  ({size:.0f} KB)")
    return 0


def cmd_rules(args: argparse.Namespace) -> int:
    for rule in rule_catalogue():
        print(f"  {rule['id']:9} [{rule['scope']}]  {rule['function']}")
    return 0


def cmd_serve(args: argparse.Namespace) -> int:
    import uvicorn

    from .api.server import create_app

    # The dashboard has no authentication. On loopback that is reasonable for a
    # single-analyst workstation; on any other interface it publishes a map of
    # which national links use broken cryptography, which is precisely the
    # targeting information an attacker wants. Refuse by default rather than
    # print a warning nobody reads.
    token = args.token or os.environ.get("CIPHERGUARD_TOKEN")
    loopback = args.host in ("127.0.0.1", "::1", "localhost")
    if not loopback and token:
        pass  # authenticated: a non-loopback bind is a deliberate deployment
    elif not loopback and not args.insecure_bind:
        print(
            f"error: refusing to bind {args.host} because the dashboard is\n"
            "       unauthenticated, and it exposes which links are weak.\n"
            "       Put it behind an authenticating reverse proxy, or pass\n"
            "       --insecure-bind if the segment is genuinely isolated.",
            file=sys.stderr,
        )
        return 1
    if not loopback and not token:
        print(_c("1;31", f"WARNING: serving unauthenticated on {args.host}"))

    app = create_app(
        model_dir=args.models,
        capture_dir=args.captures,
        baseline_db=args.db,
        allow_upload=not args.no_upload,
        auth_token=token,
        audit_log=args.audit_log,
    )
    print(f"Authentication {'enabled' if token else 'disabled (loopback only)'}"
          f"  ·  audit log {args.audit_log or 'off'}")
    print(f"Dashboard at http://{args.host}:{args.port}")
    uvicorn.run(app, host=args.host, port=args.port, log_level="warning")
    return 0


def cmd_wifi(args: argparse.Namespace) -> int:
    from .wifi.auditor import WifiAuditor

    auditor = WifiAuditor()
    print(_c("1", "\n=== CipherGuard Live Wi-Fi Security Posture Audit ==="))
    assessment = auditor.audit_current()
    iface = assessment.interface
    if not iface or iface.state.lower() != "connected":
        print(_c("31", "  [!] No connected Wi-Fi interface detected on this machine."))
        return 1

    print(f"  Connected SSID : {_c('1;36', iface.ssid)} ({iface.bssid})")
    print(f"  Radio & Band   : {iface.radio_type} | {iface.band} (Channel {iface.channel})")
    print(f"  Auth / Cipher  : {iface.authentication} / {iface.cipher}")
    print(f"  Signal Level   : {iface.signal_percent}% ({iface.rssi_dbm} dBm)")
    if iface.rx_rate_mbps:
        print(f"  Data Rates     : RX {iface.rx_rate_mbps} Mbps / TX {iface.tx_rate_mbps} Mbps")
    if iface.dns_servers:
        print(f"  DNS Resolvers  : {', '.join(iface.dns_servers)}")
    if iface.gateway_ip:
        print(f"  IPv4 Gateway   : {iface.gateway_ip}")

    score = assessment.score
    colour = "32" if score >= 80 else "33" if score >= 60 else "31"
    print(f"\n  Wireless Posture Score : {_c(colour, f'{score}/100')} (Grade {_c(colour, assessment.grade)})")
    print(f"  {assessment.summary}")

    print(f"\n  Findings ({len(assessment.findings)}):")
    for f in assessment.findings:
        fcol = "31" if f.severity in ("critical", "high") else "33" if f.severity == "medium" else "36"
        print(f"    [{_c(fcol, f.severity.upper())}] {f.title} ({f.rule_id})")
        print(f"      Subject: {f.subject}")
        print(f"      Detail:  {f.detail}")
        print(f"      Fix:     {f.remediation}")
        print()

    if assessment.networks_in_range:
        print(f"  Visible Networks in Range ({len(assessment.networks_in_range)}):")
        for n in assessment.networks_in_range:
            active_marker = " [CONNECTED]" if n.connected else ""
            print(f"    - {n.ssid:<25} {n.bssid}  {n.authentication:<16} {n.signal_percent:>3}%  (Grade {n.security_grade}){active_marker}")

    try:
        from .vpn.detector import VpnDetector
        vpn_info = VpnDetector().detect_current(iface.name, iface.dns_servers)
        print(_c("1", "\n  VPN Overlay Posture:"))
        if vpn_info.connected:
            leak_txt = _c("31", " [DNS LEAK DETECTED]") if vpn_info.dns_leak_detected else _c("32", " [Tunnel DNS Enforced]")
            print(_c("32", f"    - Active Tunnel : {vpn_info.vpn_type} on '{vpn_info.adapter_name}'{leak_txt}"))
        else:
            print(_c("33", "    - Tunnel Status : No active VPN tunnel (Direct ISP egress)"))
        if vpn_info.egress_ip:
            loc = f" ({vpn_info.egress_city}, {vpn_info.egress_country})" if vpn_info.egress_city else ""
            print(f"    - Public Egress : {vpn_info.egress_ip} | {vpn_info.egress_isp}{loc}")
    except Exception:
        pass

    return 0


def cmd_vpn(args: argparse.Namespace) -> int:
    from .vpn.detector import VpnDetector

    detector = VpnDetector()
    print(_c("1", "\n=== CipherGuard VPN Tunnel & Overlay Security Audit ==="))
    info = detector.detect_current()

    if info.connected:
        print(_c("1;32", f"  Status         : ENCRYPTED VPN TUNNEL ACTIVE ({info.vpn_type})"))
        print(f"  Tunnel Adapter : {info.adapter_name} ({info.adapter_description})")
        if info.gateway_ip:
            print(f"  Tunnel Gateway : {info.gateway_ip}")
        print(f"  Default Route  : {'Redirected through Tunnel' if info.is_default_route else 'Split-Tunnel (Local Default)'}")
        if info.dns_servers:
            print(f"  Tunnel DNS     : {', '.join(info.dns_servers)}")
        if info.dns_leak_detected:
            print(_c("1;31", f"  DNS Leak Alert : YES - Leaking queries to {info.dns_leak_details}"))
        else:
            print(_c("32", "  DNS Leak Alert : NONE (DNS queries securely contained in tunnel)"))
    else:
        print(_c("1;33", "  Status         : NO ACTIVE VPN TUNNEL (Direct Connection)"))
        print(_c("90", "  All traffic routes directly through local gateway to public ISP."))

    if info.egress_ip:
        loc = f" ({info.egress_city}, {info.egress_country})" if info.egress_city else ""
        print(f"  Public Egress  : {info.egress_ip} | {info.egress_isp}{loc}")

    print(f"\n  Findings ({len(info.findings)}):")
    for f in info.findings:
        fcol = "31" if f.severity in ("critical", "high") else "33" if f.severity == "medium" else "36"
        print(f"    [{_c(fcol, f.severity.upper())}] {f.title} ({f.rule_id})")
        print(f"      Subject: {f.subject}")
        print(f"      Detail:  {f.detail}")
        print(f"      Fix:     {f.remediation}")
        print()

    return 0


def cmd_remediate(args: argparse.Namespace) -> int:
    """Generate vendor-specific automated hardening playbooks, check syntax, and manage approvals."""
    from .pipeline import analyze
    from .remediation import PlanStore, apply_plan, build_all_plans, build_plan

    a = analyze(args.capture, model_dir=args.models)
    platform = getattr(args, "platform", None)

    if platform:
        plan = build_plan(a, platform)
        plans = [plan]
    else:
        plans = build_all_plans(a)

    store = PlanStore(args.db if hasattr(args, "db") and args.db else "cipherguard-plans.db")

    if getattr(args, "approve", None):
        print(_c("1", f"\n=== Recording Administrator Approval ==="))
        for p in plans:
            p.capture = args.capture
            store.save_plan(p)
            updated = store.update_status(p.plan_id, "APPROVED", actor=args.approve, comment="Approved via CLI")
            print(_c("1;32", f"  [APPROVED] Plan {p.plan_id} for {p.platform_name} approved by {args.approve}"))
        return 0

    if getattr(args, "dry_run", False):
        print(_c("1", f"\n=== CipherGuard Dry-Run Validation on {len(plans)} Platforms ==="))
        for p in plans:
            res = apply_plan(p, dry_run=True)
            status_tag = _c("32", "VALID") if res["success"] else _c("31", "INVALID")
            print(f"  [{status_tag}] {p.platform_name:<24} {res['lines_staged']} commands staged | {len(p.rollback_config.splitlines())} rollback lines")
        return 0

    print(_c("1", f"\n=== CipherGuard Automated Hardening & Remediation Playbooks ==="))
    print(f"  Capture : {args.capture} (Posture Score: {a.score()}/100, Grade {a.grade()})")
    print(f"  Findings Addressed : {sum(1 for f in a.findings if f.severity.value != 'info')}")

    for p in plans:
        syntax_tag = _c("32", "SYNTAX OK") if p.syntax_valid else _c("31", f"SYNTAX ERR: {', '.join(p.syntax_errors)}")
        print(_c("1;36", f"\n--- [{p.platform.upper()}] {p.platform_name} ({syntax_tag}) ---"))
        content = p.rollback_config if getattr(args, "rollback", False) else p.forward_config
        if getattr(args, "rollback", False):
            print(_c("33", "  [ROLLBACK / TEARDOWN PLAYBOOK]"))
        print(content)
        if getattr(args, "out", None):
            os.makedirs(args.out, exist_ok=True)
            prefix = "rollback" if getattr(args, "rollback", False) else "harden"
            path = os.path.join(args.out, f"{prefix}-{p.platform}.conf")
            with open(path, "w", encoding="utf-8") as fh:
                fh.write(content)
            print(f"  Wrote {path}  ({p.platform_name})")
        store.save_plan(p)

    return 0


# ---------------------------------------------------------------------------


def _add_sensor_storage_args(p: argparse.ArgumentParser) -> None:
    """Where a sensor writes and how much it may keep.

    Shared by `sensor` and `healthcheck` so that a healthcheck given the same
    flags as the sensor checks the sensor's actual configuration.
    """
    p.add_argument("--out", default="captures", help="directory for window captures")
    p.add_argument("--db", default="cipherguard-baseline.db", help="baseline store")
    p.add_argument("--max-window-mb", type=int, default=512,
                   help="byte ceiling for a single window capture")
    p.add_argument("--max-disk-mb", type=int, default=4096,
                   help="total disk ceiling for retained captures")
    p.add_argument("--no-evidence", action="store_true",
                   help="discard each capture once assessed")
    p.add_argument("--audit-log", default="cipherguard-audit.jsonl")
    p.add_argument("--audit-max-mb", type=int, default=16,
                   help="rotate the audit log at this size (0: never rotate)")
    p.add_argument("--audit-backups", type=int, default=5,
                   help="rotated audit log generations to keep")


def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(
        prog="cipherguard",
        description="Passive IPsec VPN protocol analyzer and security assessment framework",
    )
    ap.add_argument("--models", default="models", help="trained model directory")
    sub = ap.add_subparsers(dest="command", required=True)

    p = sub.add_parser("analyze", help="assess a capture file")
    p.add_argument("capture")
    p.add_argument("-v", "--verbose", action="store_true", help="show finding detail")
    p.add_argument("--json", action="store_true", help="emit JSON instead of a report")
    p.add_argument("-o", "--out", help="write the JSON report to this path")
    p.add_argument("--min-packets", type=int, default=8,
                   help="minimum ESP packets before a flow is assessed")
    p.add_argument("--disable", help="comma-separated rule IDs to skip")
    p.add_argument("--fail-under", type=int, metavar="N",
                   help="exit 2 if the posture score is below N (for CI gating)")
    p.add_argument("--audit-log", default="cipherguard-audit.jsonl",
                   help="JSON Lines audit trail path; use '' to disable")
    p.add_argument("--policy", help="JSON policy overlay to apply over the baseline")
    p.add_argument("--policy-replace", action="store_true",
                   help="replace baseline tables instead of extending them")
    p.set_defaults(func=cmd_analyze)


    p = sub.add_parser("watch", help="record against baseline and detect downgrades")
    p.add_argument("capture")
    p.add_argument("--db", default="cipherguard-baseline.db", help="baseline store path")
    p.add_argument("--fleet", action="store_true", help="print the fleet triage queue")
    p.set_defaults(func=cmd_watch)

    p = sub.add_parser("roadmap", help="rank links by post-quantum exposure")
    p.add_argument("capture")
    p.add_argument("--data-class", default="official",
                   choices=["routine", "official", "confidential", "strategic"],
                   help="how long the traffic must remain secret")
    p.add_argument("--migration-years", type=float, default=3.0)
    p.add_argument("--crqc-years", type=float, default=12.0,
                   help="planning assumption for quantum computer arrival")
    p.add_argument("--json", action="store_true")
    p.set_defaults(func=cmd_roadmap)

    p = sub.add_parser("cbom", help="export a CycloneDX cryptographic bill of materials")
    p.add_argument("capture")
    p.add_argument("-o", "--out", help="write the CBOM to this path")
    p.set_defaults(func=cmd_cbom)

    p = sub.add_parser("train", help="train the ESP inference model")
    p.add_argument("--samples", type=int, default=90)
    p.add_argument("--epochs", type=int, default=60)
    p.add_argument("--seed", type=int, default=42)
    p.add_argument("--include-real", metavar="DIR",
                   help="add labelled real captures (<capture>.label.json) from DIR; "
                        "scored leave-one-capture-out. Default: synthetic only")
    p.add_argument("--min-packets", type=int, default=8,
                   help="minimum ESP packets for a real flow to be used")
    p.set_defaults(func=cmd_train)

    p = sub.add_parser("label-check",
                       help="score ESP inference against a capture's ground-truth label")
    p.add_argument("capture", help="capture with a <capture>.label.json sidecar")
    p.add_argument("--min-packets", type=int, default=8,
                   help="minimum ESP packets before a flow is scored")
    p.add_argument("--json", action="store_true")
    p.set_defaults(func=cmd_label_check)

    p = sub.add_parser("sensor", help="continuous live capture and assessment")
    p.add_argument("interface", help="interface to monitor (a mirror/tap port)")
    p.add_argument("--window", type=int, default=60, help="seconds per capture window")
    p.add_argument("--windows", type=int, help="stop after N windows (default: forever)")
    p.add_argument("--snaplen", type=int, default=2048)
    p.add_argument("--retain", type=int, default=24,
                   help="window captures to keep as evidence")
    p.add_argument("--retain-observations", type=int, default=DEFAULT_RETAIN_PER_PEER,
                   help="baseline observations kept per link (0: no count ceiling)")
    p.add_argument("--retain-days", type=float, default=DEFAULT_RETAIN_DAYS,
                   help="drop baseline observations older than this (0: no age ceiling)")
    p.add_argument("--fail-under", type=int, metavar="N")
    _add_sensor_storage_args(p)
    p.set_defaults(func=cmd_sensor)

    p = sub.add_parser("healthcheck",
                       help="check a sensor deployment; exit 0/1/2 healthy/degraded/failed")
    _add_sensor_storage_args(p)
    p.add_argument("--stale-after", type=float, metavar="SECONDS",
                   help="last-window age that counts as degraded (default: two "
                        "windows plus 120s; failed at three times this)")
    p.add_argument("--json", action="store_true")
    p.set_defaults(func=cmd_healthcheck)

    p = sub.add_parser("verify-real",
                       help="validate the dissector against real public captures")
    p.add_argument("--dir", default=os.path.join("samples", "real"))
    p.add_argument("-v", "--verbose", action="store_true")
    p.set_defaults(func=cmd_verify_real)

    p = sub.add_parser("bench",
                       help="measure reader and pipeline throughput on a generated capture")
    p.add_argument("--packets", type=int, default=200_000,
                   help="approximate size of the generated capture")
    p.add_argument("--repeat", type=int, default=3, help="runs per path; best is reported")
    p.add_argument("--keep", metavar="PATH", help="write the capture here and keep it")
    p.add_argument("--json", action="store_true")
    p.set_defaults(func=cmd_bench)

    p = sub.add_parser("export-demo",
                       help="build a static dashboard for GitHub Pages")
    p.add_argument("-o", "--out", default="docs", help="output directory")
    p.add_argument("--captures", default="samples")
    p.set_defaults(func=cmd_export_demo)

    p = sub.add_parser("validate", help="cross-model validation and mask ablation")
    p.add_argument("--samples", type=int, default=30, help="field flows per suite")
    p.add_argument("--json", action="store_true")
    p.set_defaults(func=cmd_validate)

    p = sub.add_parser("lab", help="generate reference testbed captures")
    p.add_argument("-o", "--out", default="samples")
    p.add_argument("--list", action="store_true", help="list scenarios and exit")
    p.set_defaults(func=cmd_lab)

    p = sub.add_parser("rules", help="list the audit rule catalogue")
    p.set_defaults(func=cmd_rules)

    p = sub.add_parser("wifi", help="live audit of local Wi-Fi interface and wireless security")
    p.set_defaults(func=cmd_wifi)

    p = sub.add_parser("vpn", help="audit active VPN tunnels, route redirects, and DNS leaks")
    p.set_defaults(func=cmd_vpn)

    p = sub.add_parser("remediate", help="generate vendor-specific hardening CLI playbooks & rollback scripts")
    p.add_argument("capture", help="capture file to remediate")
    p.add_argument("--platform", choices=["cisco", "strongswan", "fortinet", "juniper"], help="target vendor platform")
    p.add_argument("-o", "--out", help="write config files to this directory")
    p.add_argument("--rollback", action="store_true", help="output the rollback/undo script instead of forward config")
    p.add_argument("--approve", metavar="ADMIN_NAME", help="record administrator approval for this plan")
    p.add_argument("--dry-run", action="store_true", help="execute dry-run syntax verification across platforms")
    p.add_argument("--db", default="cipherguard-plans.db", help="plan store database path")
    p.set_defaults(func=cmd_remediate)

    p = sub.add_parser("serve", help="run the assessment dashboard")
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--port", type=int, default=int(os.environ.get("PORT", 8000)))
    p.add_argument("--captures", default="samples", help="directory of capture files")
    p.add_argument("--db", default="cipherguard-baseline.db", help="baseline store path")
    p.add_argument("--no-upload", action="store_true", help="disable the upload endpoint")
    p.add_argument("--insecure-bind", action="store_true",
                   help="allow binding a non-loopback address without authentication")
    p.add_argument("--token", help="bearer token (or set CIPHERGUARD_TOKEN)")
    p.add_argument("--audit-log", default="cipherguard-audit.jsonl",
                   help="JSON Lines audit trail path; use '' to disable")
    p.set_defaults(func=cmd_serve)

    return ap


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return args.func(args)
    except PolicyError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 5
    except ModelSchemaError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 4
    except FileNotFoundError as exc:
        print(f"error: no such file: {exc}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
