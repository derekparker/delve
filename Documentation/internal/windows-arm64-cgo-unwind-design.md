# Windows/arm64 cgo stack unwind via PE `.pdata`

**Date:** 2026-07-27  
**Branch:** `proc/windows-arm64-cgo-unwind` (based on `fix/cgo-stacktrace-arm64`; rebase onto `master` after that PR merges)  
**Status:** Ready for review

## Problem

`TestCgoStacktrace` fails on windows/arm64 at step 1 (Go→C) with only `C.helloworld_pt2` visible, CFA `0x10`, BP `0`, then a null frame.

Clang for Windows ARM64 (llvm-mingw in CI) emits PE SEH unwind in `.pdata` / `.xdata`, not DWARF `.debug_frame` / `.eh_frame`. Delve’s PE loader only parses `.debug_frame`, so C frames have no FDE. The null-FDE fallback uses `CFA = BP+16`; default clang omits the frame pointer, so BP stays 0 and unwind aborts (failed read near address 0x8 sets `it.err`).

Separately, `arm64SwitchStack` gates `runtime.asmcgocall` and `runtime.cgocallback` on `linux` only. Windows uses the same `asm_arm64.s`, so those switches must be enabled for Go↔C stitching in the test.

This is independent of the arm64 `crosscall2` SP restore, but later test steps still need that fix (shared `arm64_arch.go`). Hence this work branches from `fix/cgo-stacktrace-arm64`.

## Goals

- Re-enable and pass `TestCgoStacktrace` on windows/arm64 (TeamCity).
- Unwind C frames that have PE ARM64 `.pdata`/`.xdata` and no DWARF FDE, for PCs after the prologue (function body).
- Enable `asmcgocall` / `cgocallback` stack switching on Windows arm64.

## Non-goals (follow-ups)

- Mid-prologue / mid-epilogue partial unwind (full Windows SEH semantics).
- Re-enabling `TestCgoStacktrace2`.
- PE `.pdata` on windows/amd64.
- Loading `.eh_frame` from PE (clang windows/arm64 does not emit it for C).
- Changing fixture `CGO_CFLAGS` to force frame pointers as a substitute for SEH.

## Approach

**Runtime fallback:** keep DWARF as primary. When `FDEForPC` misses, look up PE `.pdata` for the PC, decode `.xdata` (or packed unwind) into a `frame.FrameContext`, and continue through the existing `fixFrameUnwindContext` / register-rule path.

Rejected alternatives:

- Synthesizing DWARF FDEs at PE load time (awkward for body-only vs later mid-prolog; pollutes `frameEntries`).
- Fixture-only `-fno-omit-frame-pointer` (does not help default user binaries).

## Architecture

```text
loadBinaryInfoPE
  → (arm64) load .pdata index + .xdata bytes onto Image

advanceRegsDWARF
  → FDEForPC?
       yes → EstablishFrame → fixFrameUnwindContext
       no  → FrameContextFromPdata(pc)?
                yes → fixFrameUnwindContext
                no  → null FDE (BP) fallback (unchanged)

arm64SwitchStack
  → asmcgocall / cgocallback: linux OR windows
```

### Components

1. **PE ARM64 unwind helper** (new file(s) under `pkg/proc/`, e.g. `pe_arm64_unwind.go`)
   - Parse `.pdata` entries (8-byte records: function start RVA + flag/packed or xdata RVA).
   - Hold `.xdata` bytes; resolve RVAs with image base (`BaseOfImage` / existing PE `entryPoint` + `StaticBase` conventions).
   - `FrameContextForPC(pc) (*frame.FrameContext, bool)`.

2. **Load hook** in PE binary load path (`parseDebugFramePE` or adjacent in `loadBinaryInfoPE`), arm64 only.

3. **Unwind hook** in `advanceRegsDWARF` only: on `ErrNoFDEForPC`, call `FrameContextForPC` before the null-FDE `fixFrameUnwindContext(nil, …)` path. Do not bury PE logic inside `arm64FixFrameUnwindContext`.

4. **Stack switch** in `arm64SwitchStack`: enable existing linux logic for `windows` as well for `asmcgocall` and `cgocallback` / `cgocallback_gofunc`.

## Data model

Per PE `Image` (arm64):

- Sorted pdata slice: function begin RVA, end/length (from xdata/packed header), and either packed unwind bits or xdata RVA.
- `.xdata` section contents (byte slice).
- Ability to convert runtime PC ↔ RVA using the same base as other PE address math in Delve.

Lookup: binary search by function range; miss → `false` (caller uses null FDE).

## Decoder (body-only)

Assume the prologue has finished. Apply the full unwind code sequence to build CFA and saved-register rules:

| Unwind effect | Resulting rules (conceptual) |
|---------------|------------------------------|
| `alloc_s` / `alloc_m` | CFA = SP + allocated size |
| `save_reg` / `save_reg_x` | Restore that register from stack (LR is return address) |
| `save_fplr` / `save_fplr_x` | Restore X29 and LR from stack |
| `set_fp` / `add_fp` | BP related; CFA still driven by alloc + saves for v1 |
| `end` | Stop; `RetAddrReg` = LR |

**v1 opcodes to implement and unit-test:**  
`alloc_s`, `alloc_m`, `save_reg`, `save_reg_x`, `save_fplr`, `save_fplr_x`, `set_fp`, `add_fp`, `end`.

**Packed vs xdata:** Clang windows/arm64 cgo objects observed in investigation use Flag=0 (`.xdata` RVA), not packed unwind. v1 must fully support the Flag=0 path. For Flag≠0 (packed), either decode the packed form into the same `FrameContext` builder or treat as no match (fall through); prefer decode if small, otherwise document as follow-up and fall through so CI stays on the xdata path.

Unsupported opcode or corrupt data: treat as no pdata match (fall through to null FDE). Optional debug log; do not make stacktraces fail harder than today solely due to incomplete SEH support.

**Future:** mid-prolog/epilog by skipping codes for instructions not yet executed (document only; not in this PR).

## Stack switching

`runtime.asmcgocall` and `runtime.cgocallback` / `cgocallback_gofunc` in `arm64SwitchStack` currently run only when `runtime.GOOS == "linux"`. Extend the condition to include `windows`. Shared assembly justifies this; do not change darwin or other GOOS behavior in this PR.

## Testing

TDD:

1. **Unit tests** (any host): synthetic or captured clang `.xdata` / packed sequences → expected CFA and LR/(BP) rules. Cover at least:
   - No-FP pattern: `alloc_s` + `save_reg` (LR) + `end` (matches default clang windows/arm64).
   - With-FP pattern: `save_fplr*` + `set_fp` (or equivalent) + `end`.
2. **Integration:** remove `skipOn(..., "windows", "arm64")` from `TestCgoStacktrace` only; regenerate `Documentation/backend_test_health.md`; validate on TeamCity windows/arm64.
3. Leave `TestCgoStacktrace2` skipped; mention follow-up in the PR description.

## Error handling

- No pdata / unsupported opcode → null FDE path.
- Memory errors applying rules → existing `it.err` behavior from DWARF unwind.

## PR / git

- Branch: `proc/windows-arm64-cgo-unwind` from `fix/cgo-stacktrace-arm64`.
- After `fix/cgo-stacktrace-arm64` lands on master: rebase this branch onto master.
- Commit messages: subsystem style (`proc: ...`).
- Do not include unrelated refactors.

## Success criteria

- `TestCgoStacktrace` passes on windows/arm64 CI without skip.
- Unit tests for the v1 opcode set pass on linux CI hosts.
- No regressions to linux/arm64 cgo stacktrace behavior covered by existing tests.
