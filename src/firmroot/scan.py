"""Scan orchestrator: firmware image -> evidence -> Gemini -> report.

Usage:
  python3 -m firmroot scan <image> [--out DIR] [--no-gemini] [--keep-extract]
"""

import argparse
import json
import sys
import time
from pathlib import Path

from . import extract, services, symbols


def run_scan(image, outdir, use_gemini=True, keep_extract=True):
    t0 = time.time()
    outdir = Path(outdir)
    outdir.mkdir(parents=True, exist_ok=True)
    extract_dir = outdir / "extracted"

    # 1.1 extraction
    ext = extract.extract_firmware(image, extract_dir)
    primary = ext["primary_rootfs"]
    if not primary:
        report = {"image": str(image), "error": "no root filesystem extracted",
                  "extraction": ext, "elapsed_s": time.time() - t0}
        (outdir / "report.json").write_text(json.dumps(report, indent=2))
        return report

    rootfs = Path(primary)

    # 1.2 service enumeration
    svcs = services.enumerate_services(rootfs)

    # 1.3 symbol mapping + heuristic
    analyses = {}
    findings = []
    for svc in svcs:
        resolved = svc.get("resolved")
        if not resolved or not Path(resolved).exists():
            continue
        # strip rootfs prefix handling: resolved paths are host paths already
        ana = symbols.analyze_binary(resolved)
        analyses[svc["binary"]] = ana
        f = symbols.check_unauth_priv_write(svc, ana)
        if f:
            f["supplementary"] = symbols.supplementary_checks(rootfs, svc, ana)
            f["finding_id"] = f"F{len(findings) + 1:03d}"
            findings.append(f)

    # version fingerprint for whole image
    fw_versions = {}
    for rel in ("etc/openwrt_release", "etc/openwrt_version",
                "etc/os-release", "etc/issue.net"):
        f = rootfs / rel
        if f.is_file():
            try:
                fw_versions[rel] = f.read_text(errors="replace").strip()[:800]
            except OSError:
                pass

    evidence = {
        "image": str(image),
        "sha256": ext["sha256"],
        "primary_rootfs": primary,
        "rootfs_candidates": ext["rootfs_candidates"],
        "services_enumerated": len(svcs),
        "binaries_analyzed": len(analyses),
        "firmware_versions": fw_versions,
        "services": [{k: v for k, v in s.items() if k != "resolved"}
                     for s in svcs],
        "binary_analyses": {
            k: {kk: vv for kk, vv in a.items() if kk != "imports"}
            | {"import_count": a["import_count"]}
            for k, a in analyses.items()
        },
        "findings": findings,
        "elapsed_extract_s": time.time() - t0,
    }
    (outdir / "evidence.json").write_text(json.dumps(evidence, indent=2))

    report = dict(evidence)
    report["elapsed_s"] = time.time() - t0

    # 1.4 Gemini
    if use_gemini and findings:
        try:
            from . import gemini_client
            triage = gemini_client.call_gemini(evidence)
            report["gemini"] = triage
        except Exception as e:
            report["gemini_error"] = str(e)
    elif use_gemini:
        report["gemini"] = {"scan_summary": "No candidate findings detected.",
                            "findings": []}

    (outdir / "report.json").write_text(json.dumps(report, indent=2))
    _write_markdown(report, outdir / "report.md")
    return report


def _write_markdown(report, path):
    lines = [f"# Firmware scan: {Path(report.get('image','')).name}", ""]
    lines.append(f"- SHA256: `{report.get('sha256','')}`")
    lines.append(f"- Rootfs: `{report.get('primary_rootfs','')}`")
    lines.append(f"- Services enumerated: {report.get('services_enumerated',0)}")
    lines.append(f"- Binaries analyzed: {report.get('binaries_analyzed',0)}")
    lines.append(f"- Candidate findings: {len(report.get('findings',[]))}")
    lines.append("")
    gem = report.get("gemini") or {}
    if gem.get("scan_summary"):
        lines.append(f"**Summary:** {gem['scan_summary']}")
        lines.append("")
    # map triage by finding_id
    triage = {f.get("finding_id"): f for f in gem.get("findings", [])}
    for f in report.get("findings", []):
        t = triage.get(f["finding_id"], {})
        lines.append(f"## {f['finding_id']}: {t.get('title', f['type'])}")
        lines.append(f"- **Priority:** {t.get('priority','?')}  |  **Service:** {f['service']}  |  **Binary:** `{f['binary']}`")
        lines.append(f"- Runs as: `{f['user']}`")
        lines.append(f"- Network symbols: {', '.join(f['matched_network_symbols'])}")
        lines.append(f"- File-write symbols: {', '.join(f['matched_file_write_symbols'])}")
        for field, label in [
            ("explanation", "Explanation"), ("attack_scenario", "Attack scenario"),
            ("permanent_fix", "Permanent fix"), ("immediate_mitigation", "Immediate mitigation"),
            ("compromise_indicators", "Compromise indicators"),
        ]:
            if t.get(field):
                lines.append(f"- **{label}:** {t[field]}")
        supp = f.get("supplementary", {})
        if supp:
            lines.append(f"- Supplementary: `{json.dumps(supp)[:400]}`")
        lines.append("")
    if report.get("gemini_error"):
        lines.append(f"**Gemini error:** {report['gemini_error']}")
    path.write_text("\n".join(lines))


def main(argv=None):
    ap = argparse.ArgumentParser(prog="firmroot")
    sub = ap.add_subparsers(dest="cmd", required=True)
    sp = sub.add_parser("scan")
    sp.add_argument("image")
    sp.add_argument("--out", default=None)
    sp.add_argument("--no-gemini", action="store_true")
    sp.add_argument("--workdir", default="work")
    args = ap.parse_args(argv)

    if args.cmd == "scan":
        out = args.out or str(Path(args.workdir) / "scans" /
                              Path(args.image).stem)
        rep = run_scan(args.image, out, use_gemini=not args.no_gemini)
        n = len(rep.get("findings", []))
        print(f"services={rep.get('services_enumerated')} "
              f"binaries={rep.get('binaries_analyzed')} findings={n} "
              f"out={out}")
        if rep.get("gemini_error"):
            print(f"GEMINI ERROR: {rep['gemini_error']}", file=sys.stderr)
        return 0


if __name__ == "__main__":
    main()
