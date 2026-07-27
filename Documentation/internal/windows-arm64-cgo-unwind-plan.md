# Windows/arm64 PE pdata cgo unwind Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Unwind C frames on windows/arm64 via PE `.pdata`/`.xdata` when DWARF has no FDE, enable `asmcgocall`/`cgocallback` on Windows, and pass `TestCgoStacktrace` on windows/arm64 CI.

**Architecture:** Runtime fallback in `advanceRegsDWARF`: on `ErrNoFDEForPC`, look up PE ARM64 pdata for the PC, decode body-only unwind codes into `frame.FrameContext`, then continue existing register application. Load pdata/xdata when loading PE images (arm64 only). Extend `arm64SwitchStack` so Windows uses the same asmcgocall/cgocallback paths as Linux.

**Tech Stack:** Go, `debug/pe`, existing `pkg/dwarf/frame` + `pkg/dwarf/regnum`, Delve `pkg/proc` stack iterator.

**Spec:** [Documentation/internal/windows-arm64-cgo-unwind-design.md](windows-arm64-cgo-unwind-design.md)

## Global Constraints

- Branch base: `fix/cgo-stacktrace-arm64` (rebase onto `master` after that PR merges).
- Body-only unwind (assume prologue finished); mid-prolog is follow-up.
- v1 opcodes only: `alloc_s`, `alloc_m`, `save_reg`, `save_reg_x`, `save_fplr`, `save_fplr_x`, `set_fp`, `add_fp`, `end`; Flag=0 `.xdata` required; packed Flag≠0 may fall through.
- Unsupported opcode / corrupt data → treat as no pdata match (null FDE), do not fail harder than today.
- Only unskip `TestCgoStacktrace` on windows/arm64; leave `TestCgoStacktrace2` skipped.
- TDD: failing test first for each behavior; subsystem commit messages (`proc: …`).
- No Co-authored-by lines in commits.

## File map

| File | Responsibility |
|------|----------------|
| `pkg/proc/pe_arm64_unwind.go` | Parse pdata/xdata; decode codes → `*frame.FrameContext`; PC lookup |
| `pkg/proc/pe_arm64_unwind_test.go` | Unit tests for decode + lookup (any host) |
| `pkg/proc/bininfo.go` | `Image` field + load pdata/xdata from PE (arm64) |
| `pkg/proc/stack.go` | Hook no-FDE path to pdata |
| `pkg/proc/arm64_arch.go` | Enable asmcgocall/cgocallback for Windows |
| `pkg/proc/proc_test.go` | Remove windows/arm64 skip on `TestCgoStacktrace` |
| `Documentation/backend_test_health.md` | Regen via `_scripts/gen-backend_test_health.go` |

---

### Task 1: Decode v1 unwind codes into FrameContext

**Files:**
- Create: `pkg/proc/pe_arm64_unwind.go`
- Test: `pkg/proc/pe_arm64_unwind_test.go`

**Interfaces:**
- Produces: `func decodeARM64UnwindCodes(codes []byte) (*frame.FrameContext, bool)` — `false` if unsupported/corrupt; on success `RetAddrReg == regnum.ARM64_LR`, CFA/Regs filled for body-only unwind.

**Notes:** Unwind codes are applied in stored order (undo order). Track running SP offset from entry SP: `alloc_*` increases CFA offset; `save_*` at `[sp+#Z*8]` becomes `RuleOffset` at `-(cfaOffset - z*8)` once CFA is SP+cfaOffset. For body-only, process all codes until `end`.

- [ ] **Step 1: Write the failing test** (no-FP clang pattern)

```go
package proc

import (
	"testing"

	"github.com/go-delve/delve/pkg/dwarf/frame"
	"github.com/go-delve/delve/pkg/dwarf/regnum"
)

// Unwind bytes from clang aarch64-windows: save_reg lr@[sp+16], alloc_s 32, end.
func TestDecodeARM64UnwindCodes_SaveLRAllocS(t *testing.T) {
	codes := []byte{0xd2, 0xc2, 0x02, 0xe4}
	fctxt, ok := decodeARM64UnwindCodes(codes)
	if !ok {
		t.Fatal("expected decode success")
	}
	if fctxt.RetAddrReg != regnum.ARM64_LR {
		t.Fatalf("RetAddrReg=%d want LR", fctxt.RetAddrReg)
	}
	if fctxt.CFA.Rule != frame.RuleCFA || fctxt.CFA.Reg != regnum.ARM64_SP || fctxt.CFA.Offset != 32 {
		t.Fatalf("CFA=%+v want SP+32", fctxt.CFA)
	}
	lr := fctxt.Regs[regnum.ARM64_LR]
	if lr.Rule != frame.RuleOffset || lr.Offset != -16 {
		t.Fatalf("LR rule=%+v want Offset -16", lr)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test -count=1 -run TestDecodeARM64UnwindCodes_SaveLRAllocS ./pkg/proc/`  
Expected: FAIL — `undefined: decodeARM64UnwindCodes`

- [ ] **Step 3: Write minimal implementation**

In `pkg/proc/pe_arm64_unwind.go`:

```go
package proc

import (
	"github.com/go-delve/delve/pkg/dwarf/frame"
	"github.com/go-delve/delve/pkg/dwarf/regnum"
)

func decodeARM64UnwindCodes(codes []byte) (*frame.FrameContext, bool) {
	cfaOff := int64(0)
	regs := map[uint64]frame.DWRule{}
	i := 0
	for i < len(codes) {
		op := codes[i]
		switch {
		case op == 0xe4: // end
			i++
			goto done
		case op&0xe0 == 0x00: // alloc_s: 000xxxxx → size = xxxxx * 16
			cfaOff += int64(op&0x1f) * 16
			i++
		case op&0xc0 == 0x40: // save_fplr: 01zzzzzz
			z := int64(op & 0x3f)
			offFromCFA := -(cfaOff - z*8)
			regs[regnum.ARM64_BP] = frame.DWRule{Rule: frame.RuleOffset, Offset: offFromCFA}
			regs[regnum.ARM64_LR] = frame.DWRule{Rule: frame.RuleOffset, Offset: offFromCFA + 8}
			i++
		case op&0xc0 == 0x80: // save_fplr_x: 10zzzzzz — pre-index; body-only: treat as alloc (z+1)*8 then save at [sp+0]
			z := int64(op&0x3f) + 1
			cfaOff += z * 8
			regs[regnum.ARM64_BP] = frame.DWRule{Rule: frame.RuleOffset, Offset: -cfaOff}
			regs[regnum.ARM64_LR] = frame.DWRule{Rule: frame.RuleOffset, Offset: -cfaOff + 8}
			i++
		case op == 0xe1: // set_fp
			i++
			// BP = SP at this point in prologue; body-only CFA still from alloc/saves.
		case op == 0xe2: // add_fp: 11100010 xxxxxxxx
			if i+1 >= len(codes) {
				return nil, false
			}
			i += 2
		case op&0xf8 == 0xc8: // alloc_m: 11000xxx xxxxxxxx
			if i+1 >= len(codes) {
				return nil, false
			}
			n := (uint16(op&0x07) << 8) | uint16(codes[i+1])
			cfaOff += int64(n) * 16
			i += 2
		case op&0xfc == 0xd0: // save_reg: 110100xx xxzzzzzz
			if i+1 >= len(codes) {
				return nil, false
			}
			x := ((op & 0x03) << 2) | (codes[i+1] >> 6)
			z := int64(codes[i+1] & 0x3f)
			reg := regnum.ARM64_X0 + 19 + uint64(x)
			offFromCFA := -(cfaOff - z*8)
			regs[reg] = frame.DWRule{Rule: frame.RuleOffset, Offset: offFromCFA}
			i += 2
		case op&0xfe == 0xd4: // save_reg_x: 1101010x xxxzzzzz
			if i+1 >= len(codes) {
				return nil, false
			}
			// pre-index save: increase cfa then place reg at new sp
			x := ((op & 0x01) << 3) | (codes[i+1] >> 5)
			z := int64(codes[i+1]&0x1f) + 1
			cfaOff += z * 8
			reg := regnum.ARM64_X0 + 19 + uint64(x)
			regs[reg] = frame.DWRule{Rule: frame.RuleOffset, Offset: -cfaOff}
			i += 2
		default:
			return nil, false
		}
	}
done:
	if cfaOff == 0 && len(regs) == 0 {
		return nil, false
	}
	return &frame.FrameContext{
		RetAddrReg: regnum.ARM64_LR,
		CFA:        frame.DWRule{Rule: frame.RuleCFA, Reg: regnum.ARM64_SP, Offset: cfaOff},
		Regs:       regs,
	}, true
}
```

Fix bit-packing against [Microsoft ARM64 unwind codes](https://learn.microsoft.com/en-us/cpp/build/arm64-exception-handling) while making the test pass; the `0xd2,0xc2` pair must yield `save_reg` X=11 (x30/LR), Z=2.

- [ ] **Step 4: Run test to verify it passes**

Run: `go test -count=1 -run TestDecodeARM64UnwindCodes_SaveLRAllocS ./pkg/proc/`  
Expected: PASS

- [ ] **Step 5: Add with-FP test and implement until green**

```go
func TestDecodeARM64UnwindCodes_SaveFplrXSetFp(t *testing.T) {
	// Minimal synthetic: save_fplr_x with Z=1 → pre-index 16 bytes, then set_fp, end
	// 10zzzzzz with z=1 → 0x81; set_fp 0xe1; end 0xe4
	codes := []byte{0x81, 0xe1, 0xe4}
	fctxt, ok := decodeARM64UnwindCodes(codes)
	if !ok {
		t.Fatal("expected decode success")
	}
	if fctxt.CFA.Offset != 16 {
		t.Fatalf("CFA offset=%d want 16", fctxt.CFA.Offset)
	}
	if fctxt.Regs[regnum.ARM64_LR].Rule != frame.RuleOffset {
		t.Fatal("expected LR offset rule")
	}
	if fctxt.Regs[regnum.ARM64_BP].Rule != frame.RuleOffset {
		t.Fatal("expected BP offset rule")
	}
}
```

Run: `go test -count=1 -run 'TestDecodeARM64UnwindCodes_' ./pkg/proc/`  
Expected: PASS

- [ ] **Step 6: Commit**

```bash
git add pkg/proc/pe_arm64_unwind.go pkg/proc/pe_arm64_unwind_test.go
git commit -m "$(cat <<'EOF'
proc: decode ARM64 PE unwind codes to FrameContext

Body-only decoder for clang windows/arm64 .xdata opcodes needed
to unwind C frames without DWARF FDEs.

EOF
)"
```

---

### Task 2: Parse `.xdata` header and extract unwind code bytes

**Files:**
- Modify: `pkg/proc/pe_arm64_unwind.go`
- Modify: `pkg/proc/pe_arm64_unwind_test.go`

**Interfaces:**
- Produces: `func parseARM64Xdata(xdata []byte) (funcLen uint32, codes []byte, ok bool)`  
  - `funcLen` = function length in bytes (header field × 4)  
  - `codes` = unwind code bytes (not including padding past `end` required for tests)  
  - Requires Vers=0; on extension-word or unsupported layout return `ok=false`

- [ ] **Step 1: Write the failing test**

```go
func TestParseARM64Xdata_ClangNoFP(t *testing.T) {
	// Full xdata record from clang object: header + codes
	raw := []byte{0x09, 0x00, 0x20, 0x08, 0xd2, 0xc2, 0x02, 0xe4}
	funcLen, codes, ok := parseARM64Xdata(raw)
	if !ok {
		t.Fatal("parse failed")
	}
	if funcLen != 36 {
		t.Fatalf("funcLen=%d want 36", funcLen)
	}
	if len(codes) < 4 || codes[0] != 0xd2 || codes[3] != 0xe4 {
		t.Fatalf("codes=%x", codes)
	}
}
```

- [ ] **Step 2: Run test — expect FAIL** (`undefined: parseARM64Xdata`)

- [ ] **Step 3: Implement `parseARM64Xdata`**

Header word0 (little-endian):

- bits 0–17: FunctionLength (bytes/4)  
- bits 18–19: Vers (must be 0)  
- bit 20: X (exception data; ignore trailing handler for v1)  
- bit 21: E (epilog packed in header)  
- bits 22–26: EpilogCount  
- bits 27–31: CodeWords  

If EpilogCount and CodeWords are both 0, require a second header word (extended); for v1 tests the clang record has CodeWords=1 and E=1 — handle that path first.

Skip epilog scope words when E=0: `4 * EpilogCount` bytes after header.  
Unwind codes follow: `4 * CodeWords` bytes; pass that slice to the decoder (decoder stops at `end`).

- [ ] **Step 4: Run tests**

Run: `go test -count=1 -run 'TestParseARM64Xdata_|TestDecodeARM64UnwindCodes_' ./pkg/proc/`  
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add pkg/proc/pe_arm64_unwind.go pkg/proc/pe_arm64_unwind_test.go
git commit -m "$(cat <<'EOF'
proc: parse ARM64 PE .xdata headers for unwind codes

EOF
)"
```

---

### Task 3: pdata index and FrameContextForPC by RVA

**Files:**
- Modify: `pkg/proc/pe_arm64_unwind.go`
- Modify: `pkg/proc/pe_arm64_unwind_test.go`

**Interfaces:**
- Produces:
  - `type peARM64Unwind struct { entries []peARM64PdataEntry; xdata []byte; imageBase uint64 }`
  - `type peARM64PdataEntry struct { begin, end uint64; xdataOff uint32; packed uint32; isPacked bool }` — `begin`/`end` are runtime addresses (imageBase+RVA); `end = begin+funcLen`
  - `func (u *peARM64Unwind) FrameContextForPC(pc uint64) (*frame.FrameContext, bool)`
  - `func buildPEARM64Unwind(pdata, xdata []byte, imageBase uint64) *peARM64Unwind` — parses Flag=0 entries; Flag≠0 → skip entry or leave unimplemented (no match)

- [ ] **Step 1: Write failing lookup test**

```go
func TestPEARM64Unwind_FrameContextForPC(t *testing.T) {
	imageBase := uint64(0x100000000)
	// One pdata entry: begin RVA 0x1000, xdata at RVA 0 — store xdata as section starting at 0 for test
	xdata := []byte{0x09, 0x00, 0x20, 0x08, 0xd2, 0xc2, 0x02, 0xe4}
	// pdata: begin=0x1000, info=0 (xdata RVA 0, flag 0)
	pdata := make([]byte, 8)
	binary.LittleEndian.PutUint32(pdata[0:], 0x1000)
	binary.LittleEndian.PutUint32(pdata[4:], 0) // flag 0, xdata RVA 0
	u := buildPEARM64Unwind(pdata, xdata, imageBase)
	if u == nil {
		t.Fatal("nil unwind")
	}
	fctxt, ok := u.FrameContextForPC(imageBase + 0x1000 + 8) // inside function length 36
	if !ok || fctxt == nil {
		t.Fatal("expected hit")
	}
	if _, ok := u.FrameContextForPC(imageBase + 0x1000 + 100); ok {
		t.Fatal("expected miss past end")
	}
}
```

- [ ] **Step 2: Run — expect FAIL**

- [ ] **Step 3: Implement build + binary search + decode**

`FrameContextForPC`: find entry with `begin <= pc < end`; if packed skip (`return nil, false`); else `xdataOff` is RVA — for in-memory `xdata` slice loaded as whole section, offset = `xdataRVA - xdataSectionRVA`. For unit test with section RVA 0, offset = info field. Prefer storing `xdataOff` as offset into the `xdata []byte` at build time.

- [ ] **Step 4: Tests PASS**

- [ ] **Step 5: Commit**

```bash
git add pkg/proc/pe_arm64_unwind.go pkg/proc/pe_arm64_unwind_test.go
git commit -m "$(cat <<'EOF'
proc: index PE ARM64 .pdata for FrameContextForPC

EOF
)"
```

---

### Task 4: Load pdata/xdata from PE into Image

**Files:**
- Modify: `pkg/proc/bininfo.go` (`Image` struct; `loadBinaryInfoPE` / `parseDebugFramePE`)
- Modify: `pkg/proc/pe_arm64_unwind.go` if helpers needed for `pe.File`

**Interfaces:**
- Consumes: `buildPEARM64Unwind`
- Produces: `Image.peARM64Unwind *peARM64Unwind` (nil if not arm64 or sections missing)
- `func (bi *BinaryInfo) peARM64FrameContext(pc uint64) (*frame.FrameContext, bool)` — `PCToImage(pc)` then `image.peARM64Unwind.FrameContextForPC(pc)`

- [ ] **Step 1: Add Image field and loader**

In `Image`:

```go
peARM64Unwind *peARM64Unwind
```

In PE load (after sections available), if `bi.Arch.Name == "arm64"`:

```go
pdataSec := peFile.Section(".pdata")
xdataSec := peFile.Section(".xdata")
if pdataSec != nil && xdataSec != nil {
    pdata, _ := pdataSec.Data() // use existing peSectionData pattern from godwarf if needed
    xdata, _ := xdataSec.Data()
    // imageBase = entryPoint (BaseOfImage) as used elsewhere for PE
    image.peARM64Unwind = buildPEARM64Unwind(pdata, xdata, entryPoint)
}
```

Truncate VirtualSize like `godwarf.peSectionData` when needed. Sort entries by `begin` in `buildPEARM64Unwind`.

- [ ] **Step 2: Compile**

Run: `go test -c -o /dev/null ./pkg/proc/`  
Expected: success

- [ ] **Step 3: Commit**

```bash
git add pkg/proc/bininfo.go pkg/proc/pe_arm64_unwind.go
git commit -m "$(cat <<'EOF'
proc: load PE ARM64 .pdata/.xdata into Image

EOF
)"
```

---

### Task 5: Hook advanceRegsDWARF no-FDE path

**Files:**
- Modify: `pkg/proc/stack.go` (~708–711)

**Interfaces:**
- Consumes: `bi.peARM64FrameContext(pc)`

- [ ] **Step 1: Write a focused unit test if feasible**

Prefer relying on Task 1–3 coverage plus CI for integration. Optional: table-driven test that `peARM64FrameContext` is preferred over null FDE by constructing a minimal `BinaryInfo`/`Image` with synthetic unwind — only if cheap; otherwise skip to Step 2.

- [ ] **Step 2: Change no-FDE branch**

Replace:

```go
if _, nofde := err.(*frame.ErrNoFDEForPC); nofde {
    framectx = it.bi.Arch.fixFrameUnwindContext(nil, it.pc, it.bi)
}
```

With:

```go
if _, nofde := err.(*frame.ErrNoFDEForPC); nofde {
    if fctxt, ok := it.bi.peARM64FrameContext(it.pc); ok {
        framectx = it.bi.Arch.fixFrameUnwindContext(fctxt, it.pc, it.bi)
    } else {
        framectx = it.bi.Arch.fixFrameUnwindContext(nil, it.pc, it.bi)
    }
}
```

Ensure `fixFrameUnwindContext` with non-nil `fctxt` does not overwrite CFA for normal functions (existing crosscall2 logic only adjusts inside `crosscall2`).

- [ ] **Step 3: Run unit tests**

Run: `go test -count=1 -run 'TestDecodeARM64UnwindCodes_|TestParseARM64Xdata_|TestPEARM64Unwind_' ./pkg/proc/`  
Expected: PASS

- [ ] **Step 4: Commit**

```bash
git add pkg/proc/stack.go pkg/proc/bininfo.go
git commit -m "$(cat <<'EOF'
proc: use PE ARM64 pdata when DWARF FDE is missing

EOF
)"
```

---

### Task 6: Enable asmcgocall/cgocallback on Windows

**Files:**
- Modify: `pkg/proc/arm64_arch.go` (`arm64SwitchStack`)

- [ ] **Step 1: Replace linux-only gate**

Change:

```go
linux := runtime.GOOS == "linux"
```

To:

```go
switchStackOS := runtime.GOOS == "linux" || runtime.GOOS == "windows"
```

Replace `if linux {` on both `cgocallback*` and `asmcgocall` cases with `if switchStackOS {`. Leave other GOOS behavior unchanged.

- [ ] **Step 2: Compile**

Run: `go build ./pkg/proc/`  
Expected: success

- [ ] **Step 3: Commit**

```bash
git add pkg/proc/arm64_arch.go
git commit -m "$(cat <<'EOF'
proc: enable arm64 asmcgocall stack switch on windows

Windows shares asm_arm64.s with linux; required to stitch Go and C
frames in TestCgoStacktrace.

EOF
)"
```

---

### Task 7: Unskip TestCgoStacktrace on windows/arm64

**Files:**
- Modify: `pkg/proc/proc_test.go` (`TestCgoStacktrace` only — keep skip on `TestCgoStacktrace2`)
- Modify: `Documentation/backend_test_health.md` (generated)

- [ ] **Step 1: Remove skip and comment from TestCgoStacktrace**

Remove the block:

```go
// C frames on windows/arm64 use PE .pdata/.xdata ...
skipOn(t, "broken - cgo stacktraces", "windows", "arm64")
```

Do **not** remove the windows/arm64 skip from `TestCgoStacktrace2`.

- [ ] **Step 2: Regen health docs**

Run: `go run _scripts/gen-backend_test_health.go`  
Expected: windows/arm64 “broken - cgo stacktraces” count decreases by 1

- [ ] **Step 3: Commit**

```bash
git add pkg/proc/proc_test.go Documentation/backend_test_health.md
git commit -m "$(cat <<'EOF'
proc: enable TestCgoStacktrace on windows/arm64

PE pdata unwind plus asmcgocall switching should cover Go↔C stacks
for this test. TestCgoStacktrace2 remains skipped.

EOF
)"
```

- [ ] **Step 4: Push and validate on TeamCity windows/arm64**

```bash
git push -u fork HEAD
```

Watch `TestCgoStacktrace` on windows/arm64. If Flag≠0 packed entries appear in the fixture binary and cause misses, implement packed decode or capture CI pdata dump in a follow-up commit on this branch.

---

## Spec coverage checklist

| Spec requirement | Task |
|------------------|------|
| Runtime pdata fallback | 5 |
| Load .pdata/.xdata arm64 PE | 4 |
| Body-only v1 opcodes | 1 |
| Flag=0 xdata parse | 2–3 |
| Packed may fall through | 3 |
| asmcgocall/cgocallback on Windows | 6 |
| Unskip TestCgoStacktrace only | 7 |
| Unit tests any host | 1–3 |
| Mid-prolog / TestCgoStacktrace2 follow-up | out of plan (noted in design) |

## Execution handoff

Plan saved to `Documentation/internal/windows-arm64-cgo-unwind-plan.md` (same tree as the design; local `docs/` exclude blocks the default superpowers path).

**Two execution options:**

1. **Subagent-Driven (recommended)** — fresh subagent per task, review between tasks  
2. **Inline Execution** — execute tasks in this session with checkpoints  

Which approach?
