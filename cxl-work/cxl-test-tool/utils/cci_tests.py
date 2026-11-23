# utils/cci_tests.py
import os
import re
import json
import base64
import datetime
import html as html_lib
import utils.cxl as cxl
from utils.tools import execute_on_vm, vm_is_running, system_env

GUEST_BIN_LOCAL = os.path.expanduser("~/cxl-work/cci-tests/cci_full_suite")
GUEST_BIN_REMOTE = "/tmp/cci_full_suite"

# Factual specification and implementation notes (no assumptions)
TEST_SPECS = {
    "Identify Memory Device (0x4000)": {
        "purpose": (
            "Queries the CXL Type-3 device's firmware revision, total memory capacity, "
            "volatile vs. persistent capacity split, and Label Storage Area (LSA) size."
        ),
        "capability": "POSSIBLE & SUPPORTED — Implemented in Linux UAPI and QEMU Type-3 firmware.",
    },
    "Get Partition Info (0x4100)": {
        "purpose": (
            "Reads the currently active volatile/persistent capacity partition and "
            "checks for any pending partition changes queued for the next reset."
        ),
        "capability": "POSSIBLE & SUPPORTED — Implemented in Linux UAPI and QEMU CCLS handler.",
    },
    "LSA Set & Get Roundtrip (0x4103/0x4102)": {
        "purpose": (
            "Backs up existing LSA metadata, writes a 64-byte test pattern at offset 0x0, "
            "reads it back to verify byte-for-byte integrity, and restores original data."
        ),
        "capability": "POSSIBLE & SUPPORTED — Full read/write persistence backed by QEMU LSA memory.",
    },
    "Get Health Info (0x4200)": {
        "purpose": (
            "Queries the 18-byte CXL Health Info payload (health_status, media_status, "
            "additional_status, life_used, device_temperature, dirty_shutdown_count, ECC counters)."
        ),
        "capability": (
            "COMMAND POSSIBLE & SUPPORTED (Opcode 0x4200 executes cleanly via UAPI & QEMU) | "
            "PHYSICAL WEAR & TEMP SENSORS NOT POSSIBLE IN QEMU (QEMU firmware hardcodes CXL spec "
            "sentinel values: life_used = 0xFF [255% = Not Implemented] and "
            "device_temperature = 0x7FFF [32767 C = Not Implemented]; only runtime "
            "memdev_status [FATAL / FW_HALT / MEDIA_STATUS] and dirty_shutdown_count are modeled)."
        ),
    },
    "Get Event Records (0x0100)": {
        "purpose": (
            "Queries the Informational Event Log via CXL_MEM_COMMAND_ID_RAW to verify "
            "log flags, overflow counters, and pending event record counts."
        ),
        "capability": (
            "POSSIBLE & SUPPORTED — Requires kernel CONFIG_CXL_MEM_RAW_COMMANDS=y and "
            "output buffer <= mailbox payload size (256 bytes)."
        ),
    },
    "Set Partition Info (0x4101)": {
        "purpose": (
            "Configures the device's volatile memory partition size through the Linux "
            "UAPI and confirms both kernel validation and device firmware acceptance."
        ),
        "capability": (
            "POSSIBLE & SUPPORTED — Requires exact 10-byte payload with "
            "CXL_SET_PARTITION_IMMEDIATE_FLAG cleared (flags = 0)."
        ),
    },
    "Unsupported CCI Opcode (0xFFFF)": {
        "purpose": (
            "Sends an unallocated opcode (0xFFFF) to verify that QEMU device firmware "
            "safely rejects unknown commands with CXL_MBOX_UNSUPPORTED (0x0003)."
        ),
        "capability": "NEGATIVE BOUNDARY CHECK — Verifies firmware rejection of unimplemented opcodes.",
    },
    "Invalid UAPI Command ID (0xDEAD)": {
        "purpose": (
            "Sends an invalid command ID (0xDEAD) to /dev/cxl/memX to confirm the Linux "
            "kernel UAPI rejects malformed ioctls (ENOTTY/EINVAL) before hardware access."
        ),
        "capability": "NEGATIVE BOUNDARY CHECK — Verifies Linux kernel UAPI input gatekeeping.",
    },
    "Out-of-Range LSA Read Offset (0xFFFFFFFF)": {
        "purpose": (
            "Attempts to read LSA data beyond the device's 1 MB capacity to verify that "
            "firmware blocks out-of-bounds reads with CXL_MBOX_INVALID_INPUT (0x0002)."
        ),
        "capability": "NEGATIVE BOUNDARY CHECK — Verifies QEMU LSA bounds checking on read.",
    },
    "Truncated SET_LSA Payload (2B)": {
        "purpose": (
            "Sends a 2-byte SET_LSA request (below the 8-byte header minimum) to verify "
            "firmware catches malformed packets with CXL_MBOX_INVALID_PAYLOAD_LENGTH (0x0016)."
        ),
        "capability": "NEGATIVE BOUNDARY CHECK — Verifies QEMU minimum payload length enforcement.",
    },
    "Out-of-Range SET_LSA Write Offset (0xFFFFFFFF)": {
        "purpose": (
            "Attempts to write LSA metadata past the end of the 1 MB storage region to "
            "verify firmware prevents illegal writes with CXL_MBOX_INVALID_INPUT (0x0002)."
        ),
        "capability": "NEGATIVE BOUNDARY CHECK — Verifies QEMU LSA bounds checking on write.",
    },
    "Invalid Event Log Type (0xFF)": {
        "purpose": (
            "Requests event records from an undefined log category (0xFF) to confirm "
            "firmware rejects invalid log identifiers with CXL_MBOX_INVALID_INPUT (0x0002)."
        ),
        "capability": "NEGATIVE BOUNDARY CHECK — Verifies QEMU event log ID validation.",
    },
}

PHASE_TITLES = {
    "Week 5": "Part 1: Standard CXL 3.0 CCI Functional Operations",
    "Week 6": "Part 2: Negative Boundary, Security & Error-Handling Checks",
}


def _deploy_guest_binary():
    if not os.path.exists(GUEST_BIN_LOCAL):
        raise FileNotFoundError(f"Compiled binary not found at {GUEST_BIN_LOCAL}")
    with open(GUEST_BIN_LOCAL, "rb") as f:
        encoded = base64.b64encode(f.read()).decode("ascii")

    execute_on_vm(f"rm -f {GUEST_BIN_REMOTE}.b64 {GUEST_BIN_REMOTE}")
    chunk_size = 32768
    for i in range(0, len(encoded), chunk_size):
        chunk = encoded[i:i + chunk_size]
        execute_on_vm(f"printf '%s' '{chunk}' >> {GUEST_BIN_REMOTE}.b64")
    execute_on_vm(
        f"base64 -d {GUEST_BIN_REMOTE}.b64 > {GUEST_BIN_REMOTE} && "
        f"rm -f {GUEST_BIN_REMOTE}.b64 && chmod +x {GUEST_BIN_REMOTE}"
    )


def _format_duration(elapsed):
    try:
        sec = float(elapsed)
        return f"{sec * 1000:.2f} ms ({sec:.4f}s)"
    except (ValueError, TypeError):
        return f"{elapsed}s"


def _interpret_evidence(name, detail):
    """Decodes raw wire/sentinel values explicitly without assuming physical hardware."""
    if "0x4200" in name or "Health" in name:
        notes = []
        m_hf = re.search(r"HealthFlags=(0x[0-9a-fA-F]+)", detail)
        m_ms = re.search(r"MediaStatus=(0x[0-9a-fA-F]+)", detail)
        m_lu = re.search(r"LifeUsed=(\d+)%", detail)
        m_tp = re.search(r"Temp=(-?\d+)C", detail)

        if m_hf:
            hf = int(m_hf.group(1), 16)
            notes.append(
                f"HealthFlags={m_hf.group(1)} ({'Normal — no FATAL or FW_HALT bits set' if hf == 0 else 'Alert bits active'})"
            )
        if m_ms:
            ms = int(m_ms.group(1), 16)
            notes.append(
                f"MediaStatus={m_ms.group(1)} ({'Normal / Ready' if ms == 0 else 'Not Ready'})"
            )
        if m_lu:
            lu = int(m_lu.group(1))
            if lu == 255:
                notes.append("LifeUsed=255% (0xFF = CXL Spec Sentinel: Physical endurance sensor NOT implemented in QEMU)")
            else:
                notes.append(f"LifeUsed={lu}% (Valid physical wear reading)")
        if m_tp:
            tp = int(m_tp.group(1))
            if tp == 32767:
                notes.append("Temp=32767C (0x7FFF = CXL Spec Sentinel: Physical temperature sensor NOT implemented in QEMU)")
            else:
                notes.append(f"Temp={tp}C (Valid temperature reading)")

        if notes:
            return f"{detail}\n           Decoded  : " + " | ".join(notes)
    return detail


def _write_reports(results, dev_path, started):
    log_dir = system_env("cxl_test_log_dir") or "/tmp"
    os.makedirs(log_dir, exist_ok=True)
    ts = started.strftime("%Y%m%d_%H%M%S")
    txt_path = os.path.join(log_dir, f"cci_report_{ts}.txt")
    html_path = os.path.join(log_dir, f"cci_report_{ts}.html")

    total = len(results)
    passed = sum(1 for r in results if r["status"] == "PASS")
    skipped = sum(1 for r in results if r["status"] == "SKIP")
    failed = total - passed - skipped
    pass_rate = (passed / total * 100.0) if total else 0.0
    total_time = sum(float(r.get("elapsed", 0)) for r in results)

    # 1. Write Detailed Human-Readable Plain-Text Report
    with open(txt_path, "w") as f:
        f.write("================================================================================\n")
        f.write("                 CXL 3.0 CCI COMPLIANCE & VALIDATION TEST REPORT                \n")
        f.write("================================================================================\n")
        f.write(f"Execution Date : {started.strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write(f"Target Device  : {dev_path} (RISC-V QEMU CXL Type-3 Memory Device)\n")
        f.write(f"Overall Status : {'ALL TESTS PASSED' if failed == 0 else 'FAILURES DETECTED'}\n")
        f.write(
            f"Summary Counts : {passed} Passed | {skipped} Skipped | {failed} Failed "
            f"(Total: {total} | Pass Rate: {pass_rate:.1f}%)\n"
        )
        f.write(f"Total Runtime  : {total_time * 1000:.2f} ms ({total_time:.4f}s)\n")
        f.write("================================================================================\n\n")

        current_phase = None
        for idx, r in enumerate(results, start=1):
            if r["phase"] != current_phase:
                current_phase = r["phase"]
                section_title = PHASE_TITLES.get(current_phase, current_phase)
                f.write(f"*** {section_title.upper()} ***\n")
                f.write("=" * 80 + "\n\n")

            spec = TEST_SPECS.get(r["name"], {})
            purpose = spec.get("purpose", "Validates CXL 3.0 Component Command Interface behavior.")
            capability = spec.get("capability", "Verified against CXL 3.0 specification.")
            status_label = {
                "PASS": "PASS (Verified)",
                "SKIP": "SKIP (Bypassed)",
                "FAIL": "FAIL (Error)",
            }.get(r["status"], r["status"])
            evidence = _interpret_evidence(r["name"], r["detail"])

            f.write(f"Test #{idx:02d}   : {r['name']}\n")
            f.write(f"Category   : {r['category']} ({r['phase']})\n")
            f.write(f"Outcome    : {status_label} in {_format_duration(r['elapsed'])}\n")
            f.write(f"Feasibility: {capability}\n")
            f.write(f"Purpose    : {purpose}\n")
            f.write(f"Evidence   : {evidence}\n")
            f.write("-" * 80 + "\n\n")

    # 2. Write Detailed Human-Readable HTML Report
    cards_html = []
    for idx, r in enumerate(results, start=1):
        status = r["status"]
        badge_cls = "pass" if status == "PASS" else ("skip" if status == "SKIP" else "fail")
        spec = TEST_SPECS.get(r["name"], {})
        purpose = html_lib.escape(
            spec.get("purpose", "Validates CXL 3.0 Component Command Interface behavior.")
        )
        capability = html_lib.escape(
            spec.get("capability", "Verified against CXL 3.0 specification.")
        )
        section_title = html_lib.escape(PHASE_TITLES.get(r["phase"], r["phase"]))
        evidence_lines = _interpret_evidence(r["name"], r["detail"]).split("\n")
        evidence_html = "<br>".join(f"<code>{html_lib.escape(line.strip())}</code>" for line in evidence_lines)

        cards_html.append(f"""
        <tr>
          <td><strong>#{idx:02d}</strong></td>
          <td><span class="badge {badge_cls}">{html_lib.escape(status)}</span></td>
          <td>
            <div class="test-title">{html_lib.escape(r['name'])}</div>
            <div class="test-meta">{section_title} &bull; Category: {html_lib.escape(r['category'])}</div>
            <div class="test-cap"><strong>Support &amp; Limits:</strong> {capability}</div>
            <div class="test-desc">{purpose}</div>
          </td>
          <td>{evidence_html}</td>
          <td class="nowrap">{html_lib.escape(_format_duration(r['elapsed']))}</td>
        </tr>
        """)

    overall_banner_cls = "banner-pass" if failed == 0 else "banner-fail"
    overall_text = "ALL TESTS PASSED" if failed == 0 else f"{failed} TEST(S) FAILED"

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>CXL 3.0 CCI Compliance Test Report</title>
<style>
  body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; margin: 32px; color: #1f2328; background: #f6f8fa; }}
  .container {{ max-width: 1200px; margin: 0 auto; background: #ffffff; padding: 28px; border-radius: 10px; border: 1px solid #d0d7de; }}
  h1 {{ margin-top: 0; font-size: 22px; }}
  .meta-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap: 12px; margin: 18px 0; }}
  .meta-box {{ background: #f6f8fa; border: 1px solid #d0d7de; border-radius: 6px; padding: 12px; }}
  .meta-label {{ font-size: 12px; color: #57606a; text-transform: uppercase; letter-spacing: 0.4px; }}
  .meta-value {{ font-size: 15px; font-weight: 600; margin-top: 4px; }}
  .banner-pass {{ background: #dafbe1; color: #116329; border: 1px solid #4ac26b; padding: 10px 14px; border-radius: 6px; font-weight: 600; }}
  .banner-fail {{ background: #ffebe9; color: #82071e; border: 1px solid #ff8182; padding: 10px 14px; border-radius: 6px; font-weight: 600; }}
  table {{ border-collapse: collapse; width: 100%; margin-top: 20px; }}
  th, td {{ border: 1px solid #d0d7de; padding: 12px; text-align: left; vertical-align: top; font-size: 14px; }}
  th {{ background: #f6f8fa; font-weight: 600; }}
  .test-title {{ font-weight: 600; font-size: 15px; color: #0969da; }}
  .test-meta {{ font-size: 12px; color: #57606a; margin-top: 2px; }}
  .test-cap {{ font-size: 12.5px; color: #7d4e00; background: #fff8c5; border: 1px solid #d4a72c; padding: 5px 8px; border-radius: 4px; margin-top: 6px; }}
  .test-desc {{ font-size: 13px; color: #24292f; margin-top: 6px; line-height: 1.45; }}
  code {{ background: #f6f8fa; padding: 3px 6px; border-radius: 4px; font-size: 12px; display: inline-block; margin-bottom: 4px; }}
  .badge {{ padding: 4px 8px; border-radius: 12px; font-size: 12px; font-weight: 700; }}
  .pass {{ background: #dafbe1; color: #116329; }}
  .skip {{ background: #fff8c5; color: #7d4e00; }}
  .fail {{ background: #ffebe9; color: #82071e; }}
  .nowrap {{ white-space: nowrap; font-size: 13px; color: #57606a; }}
</style>
</head>
<body>
  <div class="container">
    <h1>CXL 3.0 CCI Compliance &amp; Validation Report</h1>
    <div class="{overall_banner_cls}">{overall_text} &mdash; {passed}/{total} Passed ({pass_rate:.1f}%)</div>
    <div class="meta-grid">
      <div class="meta-box"><div class="meta-label">Target Device</div><div class="meta-value"><code>{html_lib.escape(dev_path)}</code></div></div>
      <div class="meta-box"><div class="meta-label">Execution Timestamp</div><div class="meta-value">{started.strftime('%Y-%m-%d %H:%M:%S')}</div></div>
      <div class="meta-box"><div class="meta-label">Breakdown</div><div class="meta-value">{passed} Passed / {skipped} Skipped / {failed} Failed</div></div>
      <div class="meta-box"><div class="meta-label">Total Execution Time</div><div class="meta-value">{total_time * 1000:.2f} ms</div></div>
    </div>
    <table>
      <tr>
        <th>#</th>
        <th>Status</th>
        <th>Test Case, Feasibility &amp; Explanation</th>
        <th>Hardware / Kernel Response</th>
        <th>Duration</th>
      </tr>
      {''.join(cards_html)}
    </table>
  </div>
</body>
</html>"""

    with open(html_path, "w") as f:
        f.write(html)

    print("\n" + "=" * 72)
    print(f"FINAL SUMMARY : {passed}/{total} PASSED ({pass_rate:.1f}%) | {skipped} SKIPPED | {failed} FAILED")
    print(f"TXT Report    : {txt_path}")
    print(f"HTML Report   : {html_path}")
    print("=" * 72)


def run_cci_suite(memdev="mem0", mode="all", bin_dir=""):
    if not vm_is_running():
        print("VM is not running, skip CCI tests")
        return

    if not cxl.cxl_driver_loaded():
        cxl.load_driver()

    dev_path = memdev if memdev.startswith("/dev/") else f"/dev/cxl/{memdev}"
    started = datetime.datetime.now()

    _deploy_guest_binary()
    raw_out = execute_on_vm(f"{GUEST_BIN_REMOTE} {dev_path} {mode}") or ""

    results = []
    for line in raw_out.splitlines():
        if line.startswith("__JSON_RESULT__:"):
            payload = line.split("__JSON_RESULT__:", 1)[1]
            results = json.loads(payload)
            break

    if not results:
        print("Error: Failed to parse test results from guest:")
        print(raw_out)
        return

    current_phase = None
    for idx, r in enumerate(results, start=1):
        if r["phase"] != current_phase:
            current_phase = r["phase"]
            print(f"\n=== {PHASE_TITLES.get(current_phase, current_phase)} ===")
        spec = TEST_SPECS.get(r["name"], {})
        print(f"[{r['status']}] #{idx:02d} ({r['category']}) {r['name']} — {_format_duration(r['elapsed'])}")
        if spec.get("capability"):
            print(f"       Feasibility: {spec['capability']}")
        if spec.get("purpose"):
            print(f"       Purpose    : {spec['purpose']}")
        print(f"       Result     : {_interpret_evidence(r['name'], r['detail'])}")

    _write_reports(results, dev_path, started)
