// FuzzEvalStackOps fuzzes the expression evaluation stack machine with
// synthetic opcode programs (no call injection).
//
// Primary mode (depthCheck-valid programs only):
//
//	go test -run NONE -fuzz FuzzEvalStackOps -fuzztime=5s ./pkg/proc
//
// Optional unbounded mode (skip depthCheck filter for hardening campaigns):
//
//	go test -run NONE -fuzz FuzzEvalStackOps -fuzztime=5s -fuzzevalstackunbounded ./pkg/proc

package proc

import (
	"encoding/binary"
	"flag"
	"fmt"
	"go/constant"
	"testing"

	"github.com/go-delve/delve/pkg/dwarf/op"
	"github.com/go-delve/delve/pkg/proc/evalop"
)

// fuzzEvalStackMaxOps caps the number of opcodes decodeEvalStackOps will
// produce from a single fuzz input, so that pathological inputs can't cause
// unbounded programs to be built and executed.
const fuzzEvalStackMaxOps = 32

var fuzzEvalStackUnbounded = flag.Bool("fuzzevalstackunbounded", false, "run FuzzEvalStackOps without depthCheck filter")

// decodeEvalStackOps decodes a fuzzer-provided byte slice into a program
// (a []evalop.Op) for the eval stack machine (see
// pkg/proc/evalop/evalcompile.go and pkg/proc/evalop/ops.go).
//
// Encoding (v1):
//
//	buf[0]    = N, the number of ops to decode is (buf[0] % fuzzEvalStackMaxOps) + 1
//	then, repeated, one op per iteration:
//	  tag byte, followed by a tag-specific payload:
//	    0 = PushConst            payload: 1 kind byte + data:
//	        kind 0: 8 bytes, little-endian int64 value
//	        kind 1: 1 byte bool (nonzero=true)
//	        kind 2: 1 byte length L (L%=8) + L bytes string data
//	    1 = PushNil              payload: none
//	    2 = Pop                  payload: none
//	    3 = Dup                  payload: none
//	    4 = Roll(N)              payload: 1 byte, N = int(b) % 8
//	    5 = Jump(JumpAlways)     payload: 1 byte, target clamped to [0, N)
//	    6 = Jump(JumpIfTrue)     payload: 1 byte, target clamped to [0, N); Pop=false
//	    7 = Jump(JumpIfFalse)    payload: 1 byte, target clamped to [0, N); Pop=false
//	    8 = PushLen              payload: none
//	    9 = BoolToConst          payload: none
// Decoding stops (returning whatever ops have been decoded so far) as soon
// as the input is too short to decode the next tag or its payload, or if an
// unrecognized tag byte is seen. This keeps the decoder total: every input,
// including the empty slice, produces a valid (possibly empty) []evalop.Op.
func decodeEvalStackOps(buf []byte) []evalop.Op {
	if len(buf) == 0 {
		return nil
	}
	n := int(buf[0])%fuzzEvalStackMaxOps + 1
	buf = buf[1:]

	ops := make([]evalop.Op, 0, n)
	for len(ops) < n {
		if len(buf) < 1 {
			break
		}
		tag := buf[0]
		buf = buf[1:]
		switch tag {
		case 0: // PushConst
			if len(buf) < 1 {
				return ops
			}
			kind := buf[0]
			buf = buf[1:]
			switch kind {
			case 0: // int64
				if len(buf) < 8 {
					return ops
				}
				v := int64(binary.LittleEndian.Uint64(buf[:8]))
				buf = buf[8:]
				ops = append(ops, &evalop.PushConst{Value: constant.MakeInt64(v)})
			case 1: // bool
				if len(buf) < 1 {
					return ops
				}
				b := buf[0] != 0
				buf = buf[1:]
				ops = append(ops, &evalop.PushConst{Value: constant.MakeBool(b)})
			case 2: // string
				if len(buf) < 1 {
					return ops
				}
				strLen := int(buf[0]) % 8
				buf = buf[1:]
				if len(buf) < strLen {
					return ops
				}
				s := string(buf[:strLen])
				buf = buf[strLen:]
				ops = append(ops, &evalop.PushConst{Value: constant.MakeString(s)})
			default:
				return ops
			}

		case 1: // PushNil
			ops = append(ops, &evalop.PushNil{})

		case 2: // Pop
			ops = append(ops, &evalop.Pop{})

		case 3: // Dup
			ops = append(ops, &evalop.Dup{})

		case 4: // Roll(N)
			if len(buf) < 1 {
				return ops
			}
			rollN := int(buf[0]) % 8
			buf = buf[1:]
			ops = append(ops, &evalop.Roll{N: rollN})

		case 5: // Jump(JumpAlways)
			if len(buf) < 1 {
				return ops
			}
			target := int(buf[0]) % n
			buf = buf[1:]
			ops = append(ops, &evalop.Jump{When: evalop.JumpAlways, Target: target})

		case 6: // Jump(JumpIfTrue)
			if len(buf) < 1 {
				return ops
			}
			target := int(buf[0]) % n
			buf = buf[1:]
			ops = append(ops, &evalop.Jump{When: evalop.JumpIfTrue, Target: target})

		case 7: // Jump(JumpIfFalse)
			if len(buf) < 1 {
				return ops
			}
			target := int(buf[0]) % n
			buf = buf[1:]
			ops = append(ops, &evalop.Jump{When: evalop.JumpIfFalse, Target: target})

		case 8: // PushLen
			ops = append(ops, &evalop.PushLen{})

		case 9: // BoolToConst
			ops = append(ops, &evalop.BoolToConst{})

		default:
			// Unrecognized tag: stop decoding rather than guessing.
			return ops
		}
	}
	return ops
}

// evalStackOpDepthCheck returns the (npop, npush) pair for op, mirroring the
// semantics of the unexported (evalop.Op).depthCheck() method for exactly
// the whitelisted op types that decodeEvalStackOps can produce (see
// pkg/proc/evalop/ops.go). depthCheck() itself is unexported and can't be
// called from package proc, so this switch is kept in lockstep with it by
// hand for the small set of ops used here.
//
// ok is false for any op type not in the whitelist, so that callers can
// treat unrecognized ops as a hard rejection instead of panicking (this
// matters once evalStackOpsDepthOK is driven by a fuzzer in Task 3, where a
// panic here would be indistinguishable from a real bug under test).
func evalStackOpDepthCheck(op evalop.Op) (npop, npush int, ok bool) {
	switch op := op.(type) {
	case *evalop.PushConst:
		return 0, 1, true
	case *evalop.PushNil:
		return 0, 1, true
	case *evalop.Pop:
		return 1, 0, true
	case *evalop.Dup:
		return 1, 2, true
	case *evalop.Roll:
		// Roll{N} indexes stack[len-N-1]; need at least N+1 elements (stricter
		// than depthCheck()'s npop=1, which the compiler satisfies by construction).
		return op.N + 1, 1, true
	case *evalop.PushLen:
		return 1, 2, true
	case *evalop.BoolToConst:
		return 1, 1, true
	case *evalop.Jump:
		switch op.When {
		case evalop.JumpIfTrue, evalop.JumpIfFalse, evalop.JumpIfAllocStringChecksFail:
			if op.Pop {
				return 1, 0, true
			}
			return 1, 1, true
		default: // JumpAlways, JumpIfPinningDone
			return 0, 0, true
		}
	default:
		return 0, 0, false
	}
}

// evalStackOpsDepthOK performs a static stack-depth walk over ops, mirroring
// the join logic of (*compileCtx).depthCheck in
// pkg/proc/evalop/evalcompile.go, but without requiring a specific final
// depth: it only rejects programs that would underflow the stack or that
// have jump targets reachable with inconsistent stack depths. This lets the
// eval stack fuzzer (Task 3) restrict itself to programs that could plausibly
// have been produced by the real compiler's depth-checked output, without
// requiring them to look like a complete, well-formed expression program.
func evalStackOpsDepthOK(ops []evalop.Op) bool {
	depth := make([]int, len(ops)+1) // depth[i] is the depth of the stack before the i-th instruction
	for i := range depth {
		depth[i] = -1
	}
	depth[0] = 0

	checkAndSet := func(j, d int) bool {
		if j < 0 || j >= len(depth) {
			return false
		}
		if depth[j] < 0 {
			depth[j] = d
		}
		return d == depth[j]
	}

	for i, op := range ops {
		npop, npush, ok := evalStackOpDepthCheck(op)
		if !ok {
			return false
		}
		if depth[i] < npop {
			return false
		}
		d := depth[i] - npop + npush
		if !checkAndSet(i+1, d) {
			return false
		}
		if jmp, ok := op.(*evalop.Jump); ok {
			if !checkAndSet(jmp.Target, d) {
				return false
			}
		}
	}

	return depth[len(ops)] >= 0
}

type fuzzStackKind int

const (
	fuzzKindBool fuzzStackKind = iota
	fuzzKindOther
)

// evalStackOpsTypesOK performs a conservative abstract type walk over ops,
// rejecting programs where JumpIf/BoolToConst would require a boolean stack top
// but the whitelisted op sequence cannot supply one. This filters
// compiler-impossible type mismatches from the fuzz target so CI does not fail
// on "internal debugger error: expected boolean" while still allowing the
// unbounded mode to hunt Roll under-depth and other interpreter bugs. Jump
// join points are not merged (linear walk only), matching the conservative
// stance of evalStackOpsDepthOK.
func evalStackOpsTypesOK(ops []evalop.Op) bool {
	stack := make([]fuzzStackKind, 0, len(ops))

	pushKind := func(k fuzzStackKind) { stack = append(stack, k) }
	popKind := func() bool {
		if len(stack) < 1 {
			return false
		}
		stack = stack[:len(stack)-1]
		return true
	}
	peekKind := func() (fuzzStackKind, bool) {
		if len(stack) < 1 {
			return 0, false
		}
		return stack[len(stack)-1], true
	}

	for _, op := range ops {
		switch op := op.(type) {
		case *evalop.PushConst:
			if op.Value.Kind() == constant.Bool {
				pushKind(fuzzKindBool)
			} else {
				pushKind(fuzzKindOther)
			}
		case *evalop.PushNil:
			pushKind(fuzzKindOther)
		case *evalop.Pop:
			if !popKind() {
				return false
			}
		case *evalop.Dup:
			k, ok := peekKind()
			if !ok {
				return false
			}
			pushKind(k)
		case *evalop.Roll:
			if len(stack) < op.N+1 {
				return false
			}
			i := len(stack) - op.N - 1
			rolled := stack[i]
			copy(stack[i:], stack[i+1:])
			stack[len(stack)-1] = rolled
		case *evalop.PushLen:
			if len(stack) < 1 {
				return false
			}
			pushKind(fuzzKindOther)
		case *evalop.BoolToConst:
			k, ok := peekKind()
			if !ok || k != fuzzKindBool {
				return false
			}
			if !popKind() {
				return false
			}
			pushKind(fuzzKindBool)
		case *evalop.Jump:
			switch op.When {
			case evalop.JumpIfTrue, evalop.JumpIfFalse, evalop.JumpIfAllocStringChecksFail:
				k, ok := peekKind()
				if !ok || k != fuzzKindBool {
					return false
				}
				if op.Pop && !popKind() {
					return false
				}
			case evalop.JumpAlways, evalop.JumpIfPinningDone:
				// no type change
			default:
				return false
			}
		default:
			return false
		}
	}
	return true
}

func TestDecodeEvalStackOps_PushPop(t *testing.T) {
	ops := decodeEvalStackOps([]byte{
		2,                            // want 2 ops after mapping — pick bytes that decode to PushConst + Pop
		0,                            // PushConst
		0,                            // kind int64
		1, 0, 0, 0, 0, 0, 0, 0, // value 1
		2, // Pop
	})
	if len(ops) == 0 {
		t.Fatal("expected ops")
	}
}

func TestEvalStackOpsDepthOK_UnderflowRejected(t *testing.T) {
	ops := []evalop.Op{&evalop.Pop{}}
	if evalStackOpsDepthOK(ops) {
		t.Fatal("single Pop should fail depth check")
	}
}

func TestEvalStackOpsDepthOK_PushPopOK(t *testing.T) {
	ops := []evalop.Op{
		&evalop.PushConst{Value: constant.MakeInt64(1)},
		&evalop.Pop{},
	}
	if !evalStackOpsDepthOK(ops) {
		t.Fatal("PushConst+Pop should pass depth check")
	}
}

func TestDecodeEvalStackOps_EmptyInput(t *testing.T) {
	ops := decodeEvalStackOps(nil)
	if len(ops) != 0 {
		t.Fatalf("expected no ops for empty input, got %d", len(ops))
	}
}

func TestDecodeEvalStackOps_TruncatedPayloadStopsDecoding(t *testing.T) {
	// N says 2 ops, but the buffer only contains a single tag byte (Pop)
	// with no room for a second op: decoding should stop early rather
	// than panic or read out of bounds.
	ops := decodeEvalStackOps([]byte{2, 2})
	if len(ops) != 1 {
		t.Fatalf("expected 1 op, got %d", len(ops))
	}
	if _, ok := ops[0].(*evalop.Pop); !ok {
		t.Fatalf("expected Pop, got %T", ops[0])
	}
}

func TestDecodeEvalStackOps_UnknownTagStopsDecoding(t *testing.T) {
	// N says 2 ops: first is Pop (tag 2), second is an unrecognized tag
	// (99) which must stop decoding rather than being guessed at.
	ops := decodeEvalStackOps([]byte{2, 2, 99})
	if len(ops) != 1 {
		t.Fatalf("expected decoding to stop at the unknown tag, got %d ops", len(ops))
	}
	if _, ok := ops[0].(*evalop.Pop); !ok {
		t.Fatalf("expected Pop, got %T", ops[0])
	}
}

func TestEvalStackOpsDepthOK_NonWhitelistedOpRejected(t *testing.T) {
	// evalop.Dup{} plus a non-whitelisted op (Select, which decodeEvalStackOps
	// never produces): evalStackOpsDepthOK must reject rather than panic.
	ops := []evalop.Op{
		&evalop.PushConst{Value: constant.MakeInt64(1)},
		&evalop.Select{Name: "x"},
	}
	if evalStackOpsDepthOK(ops) {
		t.Fatal("non-whitelisted op should fail depth check")
	}
}

func TestEvalStackOpsDepthOK_EmptyOK(t *testing.T) {
	if !evalStackOpsDepthOK(nil) {
		t.Fatal("empty program should pass depth check")
	}
}

func TestEvalStackOpsDepthOK_ConsistentJumpJoinOK(t *testing.T) {
	// PushConst; Jump(Always, target=2); PushConst -- but the jump skips
	// the second PushConst, so both the fallthrough and the jump land on
	// instruction 2 with the same depth (1). Followed by two Pops so the
	// two branches end up balanced.
	ops := []evalop.Op{
		&evalop.PushConst{Value: constant.MakeInt64(1)},  // 0: depth 0 -> 1
		&evalop.Jump{When: evalop.JumpAlways, Target: 2}, // 1: depth 1 -> 1, jumps to 2 at depth 1
		&evalop.Pop{}, // 2: depth 1 -> 0 (join point, reached with depth 1 either way)
	}
	if !evalStackOpsDepthOK(ops) {
		t.Fatal("consistent jump join should pass depth check")
	}
}

func TestEvalStackOpsDepthOK_InconsistentJumpJoinRejected(t *testing.T) {
	// Instruction 3 is reachable directly with depth 2 (after two pushes)
	// and via the jump from instruction 0 with depth 1 (after one push):
	// an inconsistent join, which must be rejected.
	ops := []evalop.Op{
		&evalop.PushConst{Value: constant.MakeInt64(1)},  // 0: depth 0 -> 1
		&evalop.Jump{When: evalop.JumpAlways, Target: 3}, // 1: depth 1 -> 1, jumps to 3 at depth 1
		&evalop.PushConst{Value: constant.MakeInt64(2)},  // 2: depth 1 -> 2
		&evalop.Pop{}, // 3: reached with depth 2 (fallthrough) and depth 1 (jump) -- inconsistent
	}
	if evalStackOpsDepthOK(ops) {
		t.Fatal("inconsistent jump join should fail depth check")
	}
}

// zeroReaderStub is a minimal MemoryReadWriter that returns all-zero bytes
// for any read and panics on writes, so a stray write from a buggy opcode
// program is loud rather than silently ignored. This mirrors zeroReader in
// variables_fuzz_test.go, which can't be reused directly because that file
// is package proc_test.
type zeroReaderStub struct{}

func (*zeroReaderStub) ReadMemory(b []byte, addr uint64) (int, error) {
	for i := range b {
		b[i] = 0
	}
	return len(b), nil
}

func (*zeroReaderStub) WriteMemory(addr uint64, b []byte) (int, error) {
	panic("zeroReaderStub: unexpected write")
}

// stubEvalScopeForStackFuzz builds a minimal *EvalScope suitable for driving
// evalStack.eval directly with synthetic opcode programs, without a live
// target process. scope.g is left nil, so evalStack.eval skips the
// goroutine-stack-relative bookkeeping (spoff/bpoff/fboff/curthread) that
// requires a real target.
func stubEvalScopeForStackFuzz() *EvalScope {
	bi := NewBinaryInfo("linux", "amd64")
	return &EvalScope{
		Mem:     &zeroReaderStub{},
		BinInfo: bi,
		Regs:    op.DwarfRegisters{},
	}
}

// runEvalStackOps executes ops against a fresh stubEvalScopeForStackFuzz
// through the real evalStack machinery, recovering any panic into err so
// that callers (in particular FuzzEvalStackOps) can treat a panic the same
// way as any other reported failure instead of crashing the process.
func runEvalStackOps(ops []evalop.Op) (err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("internal debugger error: panic: %v", r)
		}
	}()
	stack := &evalStack{}
	stack.eval(stubEvalScopeForStackFuzz(), ops)
	return stack.err
}

// FuzzEvalStackOps fuzzes the expression evaluation stack machine
// (evalStack, see pkg/proc/eval.go) with synthetic opcode programs decoded
// from the raw fuzz input by decodeEvalStackOps. By default it restricts
// inputs to the subset that evalStackOpsDepthOK accepts as plausible
// compiler output and evalStackOpsTypesOK accepts as type-plausible; pass
// -fuzzevalstackunbounded to skip the depth filter for interpreter hardening
// campaigns (typesOK is still applied so JumpIf/BoolToConst on non-bool tops
// are not treated as bugs). No call injection is exercised:
// stubEvalScopeForStackFuzz leaves scope.g nil, so programs that require a
// live goroutine/target are naturally excluded by the depth/whitelist
// filtering upstream, not by this fuzz target directly.
//
//	go test -run NONE -fuzz FuzzEvalStackOps -fuzztime=5s ./pkg/proc
func FuzzEvalStackOps(f *testing.F) {
	// PushConst(1); Pop
	f.Add([]byte{2, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 2})
	// PushConst(1); Dup; Pop; Pop
	f.Add([]byte{4, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 3, 2, 2})
	// PushNil; Pop
	f.Add([]byte{2, 1, 2})
	// PushConst(1); Jump(Always, target clamped into range); Pop
	f.Add([]byte{3, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 5, 2, 2})
	// PushConst(1); PushLen; Pop; Pop
	f.Add([]byte{3, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 8, 2, 2})
	// PushConst(true); JumpIfFalse; Pop
	f.Add([]byte{2, 0, 1, 1, 7, 2, 2})
	// JumpIfFalse alone — depth-invalid, exercises decode without executing
	f.Add([]byte{0, 7, 0})
	// BoolToConst alone — depth-invalid, exercises decode without executing
	f.Add([]byte{0, 9})
	// single Pop -- rejected by the depth filter below, exercises that path
	f.Add([]byte{1, 2})

	f.Fuzz(func(t *testing.T, buf []byte) {
		ops := decodeEvalStackOps(buf)
		if len(ops) == 0 {
			return
		}
		if !*fuzzEvalStackUnbounded && !evalStackOpsDepthOK(ops) {
			return // primary mode: skip programs that can't plausibly be real
		}
		if !evalStackOpsTypesOK(ops) {
			return // skip compiler-impossible bool/non-bool mismatches
		}
		err := runEvalStackOps(ops)
		failIfInternalDebuggerError(t, err)
	})
}

func TestRunEvalStackOps_EmptyPopIsInternalOrPanicRecovered(t *testing.T) {
	// Intentionally depth-invalid; exercises recover path for harness unit test only.
	ops := []evalop.Op{&evalop.Pop{}}
	err := runEvalStackOps(ops)
	if err == nil {
		t.Fatal("expected error from empty Pop")
	}
	// Either recovered panic message or internal debugger error — must not crash the test process.
}

func TestRunEvalStackOps_DepthValidPushPop(t *testing.T) {
	ops := []evalop.Op{
		&evalop.PushConst{Value: constant.MakeInt64(1)},
		&evalop.Pop{},
	}
	err := runEvalStackOps(ops)
	failIfInternalDebuggerError(t, err)
}

func TestDecodeEvalStackOps_JumpIfAndPushLenBoolToConst(t *testing.T) {
	wantN := 4
	ops := decodeEvalStackOps([]byte{
		3, // (3 % 32) + 1 = 4 ops
		0, 0, 1, 0, 0, 0, 0, 0, 0, 0, // PushConst(1): tag + kind + 8-byte payload
		6, 3, // JumpIfTrue target = 3 % 4 = 3
		0, 0, 2, 0, 0, 0, 0, 0, 0, 0, // PushConst(2)
		2, // Pop
	})
	if len(ops) != wantN {
		t.Fatalf("expected %d ops, got %d", wantN, len(ops))
	}
	jmp, ok := ops[1].(*evalop.Jump)
	if !ok || jmp.When != evalop.JumpIfTrue || jmp.Target != 3 || jmp.Pop {
		t.Fatalf("op 1: got %+v, want JumpIfTrue target=3 Pop=false", ops[1])
	}

	opsFalse := decodeEvalStackOps([]byte{0, 7, 1}) // N=1, JumpIfFalse target=1%1=0
	if len(opsFalse) != 1 {
		t.Fatalf("expected 1 JumpIfFalse op, got %d", len(opsFalse))
	}
	jmpFalse, ok := opsFalse[0].(*evalop.Jump)
	if !ok || jmpFalse.When != evalop.JumpIfFalse || jmpFalse.Target != 0 || jmpFalse.Pop {
		t.Fatalf("got %+v, want JumpIfFalse target=0 Pop=false", opsFalse[0])
	}

	opsPushLen := decodeEvalStackOps([]byte{0, 8})
	if len(opsPushLen) != 1 {
		t.Fatalf("expected 1 PushLen op, got %d", len(opsPushLen))
	}
	if _, ok := opsPushLen[0].(*evalop.PushLen); !ok {
		t.Fatalf("expected PushLen, got %T", opsPushLen[0])
	}

	opsBoolToConst := decodeEvalStackOps([]byte{0, 9})
	if len(opsBoolToConst) != 1 {
		t.Fatalf("expected 1 BoolToConst op, got %d", len(opsBoolToConst))
	}
	if _, ok := opsBoolToConst[0].(*evalop.BoolToConst); !ok {
		t.Fatalf("expected BoolToConst, got %T", opsBoolToConst[0])
	}

	// Unknown tag after PushLen must stop decoding (not guess).
	opsUnknown := decodeEvalStackOps([]byte{2, 8, 10, 9})
	if len(opsUnknown) != 1 {
		t.Fatalf("expected decoding to stop at unknown tag, got %d ops", len(opsUnknown))
	}
	if _, ok := opsUnknown[0].(*evalop.PushLen); !ok {
		t.Fatalf("expected PushLen before unknown tag, got %T", opsUnknown[0])
	}
}

func TestEvalStackOpsDepthOK_JumpIfTrue(t *testing.T) {
	// JumpIfTrue with Pop=false keeps the bool on stack; both fallthrough
	// and taken-jump paths reach the final Pop with depth 1.
	ops := []evalop.Op{
		&evalop.PushConst{Value: constant.MakeBool(true)},
		&evalop.Jump{When: evalop.JumpIfTrue, Target: 2},
		&evalop.Pop{},
	}
	if !evalStackOpsDepthOK(ops) {
		t.Fatal("expected depth-ok JumpIfTrue program")
	}
}

func TestEvalStackOpsTypesOK_IntJumpIfRejected(t *testing.T) {
	ops := []evalop.Op{
		&evalop.PushConst{Value: constant.MakeInt64(1)},
		&evalop.Jump{When: evalop.JumpIfFalse, Target: 2},
		&evalop.Pop{},
	}
	if evalStackOpsTypesOK(ops) {
		t.Fatal("JumpIf on int top should fail type check")
	}
}

func TestEvalStackOpsTypesOK_BoolJumpIfOK(t *testing.T) {
	ops := []evalop.Op{
		&evalop.PushConst{Value: constant.MakeBool(true)},
		&evalop.Jump{When: evalop.JumpIfFalse, Target: 2},
		&evalop.Pop{},
	}
	if !evalStackOpsTypesOK(ops) {
		t.Fatal("JumpIf on bool top should pass type check")
	}
}

func TestDecodeEvalStackOps_PushConstBool(t *testing.T) {
	ops := decodeEvalStackOps([]byte{1, 0, 1, 1}) // PushConst(true)
	if len(ops) != 1 {
		t.Fatalf("expected 1 op, got %d", len(ops))
	}
	pc, ok := ops[0].(*evalop.PushConst)
	if !ok {
		t.Fatalf("expected PushConst, got %T", ops[0])
	}
	if pc.Value.Kind() != constant.Bool {
		t.Fatalf("expected bool const, got %v", pc.Value.Kind())
	}
	if !constant.BoolVal(pc.Value) {
		t.Fatal("expected true")
	}
}

func TestRunEvalStackOps_BoolToConstAndPushLen(t *testing.T) {
	boolOps := []evalop.Op{
		&evalop.PushConst{Value: constant.MakeBool(true)},
		&evalop.BoolToConst{},
	}
	failIfInternalDebuggerError(t, runEvalStackOps(boolOps))

	strOps := []evalop.Op{
		&evalop.PushConst{Value: constant.MakeString("hello")},
		&evalop.PushLen{},
		&evalop.Pop{},
		&evalop.Pop{},
	}
	failIfInternalDebuggerError(t, runEvalStackOps(strOps))
}
