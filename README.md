# CXL Device Emulation & CCI Verification on QEMU RISC-V

End-to-end emulation, firmware compliance patching, and automated CXL Component Command Interface (CCI) mailbox verification for a **CXL 3.0 Type-3 Memory Device** running on **RISC-V QEMU (`qemu-system-riscv64`)**.

---

## Overview

This repository provides a complete, reproducible software stack for validating CXL 3.0 Type-3 device behavior and Linux CXL UAPI (`CXL_MEM_SEND_COMMAND`) interactions without physical CXL hardware:

* **QEMU RISC-V Type-3 Emulation (`qemu/`):** Emulates a 512 MiB CXL Type-3 memory device (256 MiB Volatile + 256 MiB Persistent memory + 1 MiB Label Storage Area) on the RISC-V `virt` machine, patched for CXL 3.0 dynamic partition alignment (`partition_align = 1`) and staged/immediate `SET_PARTITION_INFO` (`0x4101`) compliance.
* **Linux CXL Subsystem (`linux/`):** Binds the emulated PCIe/DVSEC device to `/dev/cxl/mem0`, exposing 25 mailbox commands to user space via `cxl-cli`, `ndctl`, and raw UAPI `ioctl` calls.
* **Static RISC-V CCI Test Suite (`cxl-work/cci-tests/`):** Standalone static C test binaries (`cci_full_suite` and `test_set_partition`) executing 12 positive and negative CXL 3.0 mailbox compliance checks.
* **Automated Test Harness (`cxl-work/cxl-test-tool/`):** Python orchestrator (`cxl-tool.py`) that cross-compiles/deploys test binaries to the RISC-V guest over SSH, executes the suite, and generates timestamped pass/fail reports.

---

## Architecture

```text
┌───────────────────────────┐      SSH / UAPI       ┌───────────────────────────────┐
│   x86_64 Host Harness     │ ────────────────────▶ │     RISC-V Linux Guest        │
│  cxl-tool.py Orchestrator │                       │  cci_full_suite / /dev/cxl/*  │
└───────────────────────────┘                       └───────────────┬───────────────┘
                                                                    │ CXL_MEM_SEND_COMMAND
                                                                    ▼
                                                    ┌───────────────────────────────┐
                                                    │   QEMU RISC-V Type-3 Device   │
                                                    │ 256MB Vol + 256MB PMEM + 1MB  │
                                                    │  cxl-mailbox-utils.c (0x4101) │
                                                    └───────────────────────────────┘
```

---

## Repository Structure

```text
.
├── qemu/                           # QEMU source with CXL 3.0 partition compliance patch
│   ├── hw/cxl/cxl-mailbox-utils.c  # Patched IDENTIFY, GET_PARTITION_INFO, SET_PARTITION_INFO
│   └── include/hw/cxl/cxl_device.h # Added next_vmem_size & next_pmem_size state tracking
├── linux/                          # RISC-V Linux kernel source with CXL subsystem enabled
├── warp-pipe/                      # Inter-VM / PCIe-CXL transport pipe integration
└── cxl-work/
    ├── cci-tests/                  # Static RISC-V C test suite
    │   ├── cci_full_suite.c        # 12-test positive & negative CCI compliance suite
    │   ├── test_set_partition.c    # Standalone SET_PARTITION_INFO (0x4101) verifier
    │   └── Makefile                # riscv64-linux-gnu-gcc static build rules
    └── cxl-test-tool/              # Extended CXL automation harness
        └── cxl-tool.py             # CLI wrapper & report generator
```

---

## Key Firmware Enhancement (CXL 3.0 Partition Compliance)

Upstream QEMU reports `partition_align = 0` in `IDENTIFY (0x4000)` and hardcodes `next_vmem = 0` / `next_pmem = 0` in `GET_PARTITION_INFO (0x4100)`, causing compliance tools to skip partition reconfiguration tests.

Our QEMU patch updates `hw/cxl/cxl-mailbox-utils.c` and `include/hw/cxl/cxl_device.h` to achieve full CXL 3.0 specification compliance:
1. **Partition Alignment Advertisement (`0x4000`):** Sets `id->partition_align = 1` (256 MiB unit granularity) whenever static memory capacity is configured.
2. **Pending State Tracking (`0x4100`):** Tracks `next_vmem_size` and `next_pmem_size` in `CXLDeviceState` and returns them in bytes `16..31` of `GET_PARTITION_INFO`.
3. **Staged & Immediate Execution (`0x4101`):**
   * `flags == 0`: Stages new capacities into `NextVol` / `NextPMEM` for the next warm/cold reset (and clears `Next*` back to `0` when restored to the active layout).
   * `flags & 0x1` (`IMMEDIATE`): Mutates active `vmem_size` and `pmem_size` immediately.

---

## Quick Start

### 1. Build QEMU for RISC-V with CXL Support
```bash
cd qemu/build
ninja qemu-system-riscv64
```

### 2. Cross-Compile the Static RISC-V CCI Test Suite
```bash
cd cxl-work/cci-tests
make clean && make
```
This produces static `riscv64` ELF binaries (`cci_full_suite` and `test_set_partition`).

### 3. Boot RISC-V Guest & Verify CXL Enumeration
Inside the booted RISC-V Linux guest, verify PCIe and CXL subsystem binding:
```bash
lspci -v
ls -l /dev/cxl/mem0
cxl list
ndctl list
```

### 4. Run Automated Compliance Verification
From the host harness (`cxl-work/cxl-test-tool`):
```bash
python3 cxl-tool.py --cci-test all --cci-dev mem0
```
Or run individual test binaries directly inside the RISC-V guest:
```bash
./cci_full_suite /dev/cxl/mem0 all
./test_set_partition /dev/cxl/mem0 --volatile-units 0
```

---

## Test Coverage Matrix

### Positive Functional Suite (6/6 PASS)

| # | Test Case | Opcode | Verification Criteria |
| :- | :--- | :--- | :--- |
| **01** | Identify Memory Device | `0x4000` | Verifies 69B payload, 512 MiB total capacity, 1 MiB LSA, and `partition_align = 1` |
| **02** | Get Partition Info | `0x4100` | Reads 32B active/next volatile & persistent capacities |
| **03** | LSA Read/Write Roundtrip | `0x4102` / `0x4103` | Writes 64B test pattern to LSA, verifies readback, and restores original bytes |
| **04** | Get Health Info | `0x4200` | Queries 18B media health, life used, and temperature status |
| **05** | Get Event Records | `0x0100` | Polls Informational event log via `CXL_MEM_COMMAND_ID_RAW` |
| **06** | Set Partition Info | `0x4101` | Stages volatile/PMEM split, verifies `NextVol`/`NextPMEM` via `0x4100`, and restores initial state |

### Negative & Boundary Suite (6/6 PASS)

| # | Negative Scenario | Expected Behavior |
| :- | :--- | :--- |
| **07** | Unsupported Opcode (`0xFFFF`) | Rejected cleanly by kernel UAPI / device firmware |
| **08** | Invalid Command ID (`0xDEAD`) | Blocked by Linux CXL driver (`ENOTTY` / `EINVAL`) |
| **09** | Out-of-Bounds LSA Read (`0xFFFFFFFF`) | Returns CXL CCI `Invalid Input` (`0x0002`) |
| **10** | Out-of-Bounds LSA Write (`0xFFFFFFFF`) | Returns CXL CCI `Invalid Input` (`0x0002`) |
| **11** | Truncated `SET_LSA` Payload (`2B`) | Rejected prior to device MMIO submission |
| **12** | Invalid Event Log Selector (`0xFF`) | Denied cleanly by firmware event log handler |

---

## References
* [CXL 3.0 Specification](https://computeexpresslink.org/wp-content/uploads/2024/02/CXL-3.0-Specification.pdf) — Section 8.2.9 (Memory Device Commands & CCI Mailbox)
* Linux Kernel Documentation — `Documentation/driver-api/cxl/theory-of-operation.rst`
* QEMU CXL Emulation — `hw/cxl/cxl-mailbox-utils.c`