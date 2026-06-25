# GDB-Style Universal PC Adjustment Solution

## Overview

This is an alternative fix to PR #4374 that follows GDB's approach more closely by introducing a `CanonicalPC()` method that universally adjusts PC-1 for all non-top, non-signal frames.

## Implementation

### New Method: `CanonicalPC()`

```go
// CanonicalPC returns the PC adjusted for use in lookups (function, line, FDE).
// Following GDB's approach, for non-top, non-signal frames, we return pc-1.
//
// Rationale (from GDB's gdb/frame.c:get_frame_address_in_block):
// "Calling get_frame_pc returns the resume address for THIS_FRAME.
//  Normally the resume address is inside the body of the function
//  associated with THIS_FRAME, but there is a special case: when
//  calling a function which the compiler knows will never return
//  (for instance abort), the call may be the very last instruction
//  in the calling function. The resume address will point after the
//  call and may be at the beginning of a different function entirely."
//
// By subtracting 1 from the PC, we ensure lookups attribute the frame
// to the correct function - the one containing the call, not the next
// function in memory.
//
// This adjustment is safe even when PC is not at a function boundary,
// because lookups use address ranges that include PC-1 when PC is
// genuinely within the function body.
func (it *stackIterator) CanonicalPC() uint64 {
	// Don't adjust the top frame (actual execution point) or signal returns
	if it.top || it.sigret || it.pc == 0 {
		return it.pc
	}
	return it.pc - 1
}
```

### Changes to Stack Unwinding

1. **DWARF FDE Lookup** (`advanceRegsDWARF`):
```go
canonicalPC := it.CanonicalPC()
fde, err := it.bi.frameEntries.FDEForPC(canonicalPC)
```

2. **Function/Line Lookup** (`newStackframe`):
```go
canonicalPC := it.CanonicalPC()
f, l, fn := it.bi.PCToLine(canonicalPC)
```

## Comparison with PR #4374

### PR #4374 Approach (Narrow Fix)

```go
// Only adjusts when PC is EXACTLY at C function entry
if !it.top && !it.sigret && it.pc > 0 {
    if fn := it.bi.PCToFunc(it.pc); fn != nil && it.pc == fn.Entry && !fn.cu.isgo {
        if pfn := it.bi.PCToFunc(it.pc - 1); pfn != nil && pfn != fn {
            it.pc--
        }
    }
}
```

**Triggers when:**
- PC is exactly at a C function's entry point
- PC-1 belongs to a different function

**Limitations:**
- Only handles the specific case of PC at exact function entry
- Only applies to C functions
- Only fixes stack unwinding, not other PC-based lookups
- Requires multiple PCToFunc calls

### GDB-Style Approach (Universal Fix)

**Triggers when:**
- Frame is not the top frame
- Frame is not a signal return
- PC is non-zero

**Advantages:**
1. **More comprehensive**: Handles all cases where return address attribution might be wrong
2. **Simpler logic**: Single method, no complex conditionals
3. **Language agnostic**: Works for both C and Go code
4. **Consistent**: Same adjustment for all lookups (FDE, function, line)
5. **Better aligned with GDB**: Proven approach from a mature debugger

**Potential Concerns:**
1. **Broader impact**: Changes behavior for all frames, not just problematic ones
2. **More testing needed**: Need to verify it doesn't break existing functionality
3. **Conceptually different**: Changes from "fix specific bug" to "change PC semantics"

## Testing Strategy

### Test Cases

1. **Original issue** (assert in C code):
```c
void test1(void) { assert(0); }
void test2(void) { test1(); }
void test3(void) { test2(); }
```
Expected: All three functions appear in backtrace

2. **abort() variant**:
```c
void crash(void) { abort(); }
void caller(void) { crash(); }
```
Expected: caller() appears in backtrace

3. **exit() variant**:
```c
void quit(void) { exit(1); }
void caller(void) { quit(); }
```
Expected: caller() appears in backtrace

4. **Go/C boundary**:
```go
func goFunc() { C.noreturn_c_func() }
```
Expected: goFunc() appears in backtrace

5. **Multiple levels**:
Deep call chains ending in noreturn

### Regression Testing

Need to verify existing tests still pass:
- `pkg/proc/stack_test.go`
- `pkg/proc/core/core_test.go`
- Integration tests in `service/test/`

## Architecture Considerations

### Why PC-1 is Safe

1. **Address Range Lookups**: Functions and DWARF ranges use [start, end) intervals
   - If PC is within a function, PC-1 is also within it
   - If PC is at next function's entry, PC-1 is in the correct (previous) function

2. **Instruction Boundaries**: Even on fixed-width ISAs (ARM64), lookups use address ranges, not instruction alignment
   - PCToFunc, FDEForPC, PCToLine all use range checks
   - They don't require PC to be at an instruction boundary

3. **Edge Cases**:
   - PC=0: Guarded by `it.pc == 0` check
   - Top frame: Excluded (actual crash/break location)
   - Signal frames: Excluded (special handling required)

## Recommendation

The GDB-style approach is **more robust and future-proof** than PR #4374's narrow fix:

1. **Handles more cases**: Not limited to exact function entry
2. **Simpler to maintain**: Clear semantics, single method
3. **Battle-tested**: GDB has used this approach for decades
4. **Comprehensive**: Fixes lookups across the board, not just unwinding

However, it requires more extensive testing to ensure no regressions.

## Migration Path

If we want to adopt the GDB-style approach:

1. **Phase 1**: Keep PR #4374's fix as-is for immediate relief
2. **Phase 2**: Implement CanonicalPC() and run extensive testing
3. **Phase 3**: If testing passes, replace narrow fix with universal approach
4. **Phase 4**: Extend to other PC-based lookups (breakpoints, etc.)

Or we can go directly with the GDB-style approach if we're confident in the testing.

## Files Changed

- `pkg/proc/stack.go`:
  - Added `CanonicalPC()` method
  - Modified `advanceRegsDWARF()` to use canonical PC for FDE lookup
  - Modified `newStackframe()` to use canonical PC for function/line lookup

## Build and Test

```bash
# Build
make build

# Run existing tests
go test ./pkg/proc/...
go test ./pkg/proc/core/...

# Test with core dump
ulimit -c unlimited
CGO_CFLAGS="-g" go build -gcflags=all="-N -l" -o /tmp/test _fixtures/cgocoreassert.go
/tmp/test  # Will crash and generate core
./dlv core /tmp/test /path/to/core
(dlv) bt  # Should show test1, test2, test3
```

## Conclusion

The GDB-style solution is architecturally superior but requires more validation. It represents a shift from "fixing a bug" to "correcting PC semantics for stack frames," which is the right long-term approach but needs careful rollout.
