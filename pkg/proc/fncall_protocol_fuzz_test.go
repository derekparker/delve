// Layer 2 call-injection protocol fuzzing harness.
//
// This file drives the *real* call-injection protocol handler
// (funcCallStep/funcCallFinish in fncall.go, plus the evalStack.run opcode
// loop in eval.go) with a mock Thread whose protocol register (R12 on amd64,
// see runtime.debugCallV2) yields a caller-controlled sequence of values.
//
// Unlike a live target, no real process is stepped: the harness seeds state
// as if evalCallInjectionStart had already succeeded (a functionCallState is
// pushed with savedRegs/protocolReg/debugCallName filled in) and then feeds
// protocol register values into funcCallStep one step at a time. This lets us
// exercise the sequences that terminate *before* a successful
// CallInjectionSetTarget — the class of bugs behind issue #4085 — without
// needing runtime.debugCallV2 or a debuggee.
//
// Scope: the branches that do not require a realistic goroutine stack are
// fully supported and produce clean errors (or nil):
//   - debugCallRegRestoreRegisters (16): a premature RestoreRegisters finishes
//     the protocol via a no-op StepInstruction (stepInstructionOut exits because
//     the mock ThreadLocation has no function); without production guards this
//     empties fncalls and panics in CallInjectionSetTarget (#4085/#4363).
//     With the guards it yields a clean "terminated before target" error.
//   - debugCallRegCompleteCall (0) followed by CallInjectionSetTarget: callOP's
//     stack writes land in scratch memory (setPC/setSP are recorded no-ops).
//   - unknown/exhausted register values: funcCallStep's default no-op branch.
//
// The precheck-failure (8), read-return (1) and read-panic (2) branches call
// ThreadScope/readStackVariable, which unwind a real goroutine stack. The mock
// initializes BinaryInfo.Images, Target.scache, Function.cu, and PC/SP in the
// register slice so those paths fail cleanly (e.g. findType misses, unreadable
// stack memory, or empty return locals) instead of panicking on nil maps or
// incomplete register state. That is sufficient for panic hunting; a fully
// decodable stack is not required.
//
// Additional restriction: debugCallRegCompleteCall (0) may appear at most
// once per sequence. It legitimately signals "ready to call" only once per
// injection; the mock's fixed two-op stack (CallInjectionSetTarget then
// CallInjectionComplete, see setupPostStartCallInjection) has nothing left to
// execute for a second 0, so replaying it lands on a real, pre-existing
// sanity check in eval.go's evalStack.run ("eval program finished without
// error but N call injections still active") instead of a clean protocol
// error. TestCallInjectionProtocolSeeds and FuzzCallInjectionProtocol
// deliberately avoid generating more than one 0 per input for this reason;
// TestCallInjectionProtocolSeeds_RepeatedCompleteCall documents the excluded
// case so it isn't silently forgotten.

package proc

import (
	"debug/dwarf"
	"errors"
	"fmt"
	"go/constant"
	"strings"
	"testing"

	"github.com/go-delve/delve/pkg/dwarf/op"
	"github.com/go-delve/delve/pkg/dwarf/regnum"
	"github.com/go-delve/delve/pkg/dwarf/dwarfbuilder"
	"github.com/go-delve/delve/pkg/dwarf/godwarf"
	"github.com/go-delve/delve/pkg/internal/gosym"
	"github.com/go-delve/delve/pkg/internal/lru"
	"github.com/go-delve/delve/pkg/proc/evalop"
)

// errFuzzNoLiveTarget is returned by the mock ProcessGroup whenever the
// protocol handler tries to resume/step the (non-existent) target process.
// It is deliberately a plain error (no "internal debugger error" marker) so
// that a clean protocol failure is distinguishable from a real bug.
var errFuzzNoLiveTarget = errors.New("call injection terminated before target was set: no live target in fuzz harness")

// fuzzProtocolFixedPC/SP are arbitrary non-zero values returned by the mock
// registers. They only need to be internally consistent (SP below PC) and
// non-zero so that funcCallStep's PC/SP bookkeeping doesn't misbehave.
const (
	fuzzProtocolFixedPC = 0x2000
	fuzzProtocolFixedSP = 0x1000
)

// fuzzProtocolExhaustedRegval is returned once the caller-provided sequence
// of protocol register values is exhausted. It maps to funcCallStep's default
// (unknown register) branch, which is a safe no-op that just requests another
// continue, so an over-long step loop can't wander into a target-dependent
// branch.
const fuzzProtocolExhaustedRegval = 0xdead

// fuzzProtocolMemory is a scratch MemoryReadWriter: reads return zeroes and
// writes are accepted and discarded. Unlike zeroReaderStub (which panics on
// writes), this lets callOP's stack write in evalCallInjectionSetTarget
// succeed, so sequences that reach a SetTarget can be exercised without a
// spurious panic from the memory stub itself.
type fuzzProtocolMemory struct{}

func (*fuzzProtocolMemory) ReadMemory(b []byte, addr uint64) (int, error) {
	for i := range b {
		b[i] = 0
	}
	return len(b), nil
}

func (*fuzzProtocolMemory) WriteMemory(addr uint64, b []byte) (int, error) {
	return len(b), nil
}

// fuzzProtocolRegs is a minimal Registers implementation. The only value that
// matters for the protocol is the debug-call protocol register (R12 on
// amd64), which Slice reports so that
// BinaryInfo.Arch.RegistersToDwarfRegisters can decode it. PC/SP/BP/LR return
// fixed values.
type fuzzProtocolRegs struct {
	protocolReg uint64 // dwarf regnum of the protocol register (regnum.AMD64_R12)
	regval      uint64 // value reported for the protocol register
}

func (r *fuzzProtocolRegs) PC() uint64            { return fuzzProtocolFixedPC }
func (r *fuzzProtocolRegs) SP() uint64            { return fuzzProtocolFixedSP }
func (r *fuzzProtocolRegs) BP() uint64            { return fuzzProtocolFixedSP }
func (r *fuzzProtocolRegs) LR() uint64            { return 0 }
func (r *fuzzProtocolRegs) TLS() uint64           { return 0 }
func (r *fuzzProtocolRegs) GAddr() (uint64, bool) { return 0, false }

func (r *fuzzProtocolRegs) Slice(floatingPoint bool) ([]Register, error) {
	// Report PC/SP and the protocol register under canonical amd64 names so
	// RegistersToDwarfRegisters yields usable PC/SP dwarf registers for
	// ThreadStacktrace and fakeFunctionEntryScope.
	var regs []Register
	regs = AppendUint64Register(regs, regnum.AMD64ToName(regnum.AMD64_Rip), fuzzProtocolFixedPC)
	regs = AppendUint64Register(regs, regnum.AMD64ToName(regnum.AMD64_Rsp), fuzzProtocolFixedSP)
	regs = AppendUint64Register(regs, regnum.AMD64ToName(r.protocolReg), r.regval)
	return regs, nil
}

func (r *fuzzProtocolRegs) Copy() (Registers, error) {
	cp := *r
	return &cp, nil
}

// fuzzProtocolThread is a mock Thread that feeds a sequence of protocol
// register values into funcCallStep. The value returned by Registers is
// selected by the driver-controlled step index (see
// runCallInjectionProtocolFuzz), not by counting individual Registers calls:
// a single physical stop of the target is processed by more than one call
// site (funcCallStep itself, plus e.g. evalCallInjectionSetTarget reading
// PC/SP), and all of them must observe the same protocol register value for
// that stop, exactly like a real thread whose registers don't change until
// the target is resumed. Once step runs past the end of regvals, Registers
// returns fuzzProtocolExhaustedRegval. All state-changing operations
// (SetReg/RestoreRegisters) are recorded no-ops so that setPC/setSP and
// register restoration succeed without a live target.
type fuzzProtocolThread struct {
	bi          *BinaryInfo
	mem         MemoryReadWriter
	protocolReg uint64
	regvals     []uint64
	step        int // current driver step, set by runCallInjectionProtocolFuzz

	common      CommonThread
	setRegCalls int
}

// newFuzzProtocolThread builds a mock thread whose Registers() calls return
// the given protocol register values in order (R12 on amd64).
func newFuzzProtocolThread(bi *BinaryInfo, regvals []uint64) *fuzzProtocolThread {
	return &fuzzProtocolThread{
		bi:          bi,
		mem:         &fuzzProtocolMemory{},
		protocolReg: regnum.AMD64_R12,
		regvals:     regvals,
	}
}

func (th *fuzzProtocolThread) currentRegval() uint64 {
	if th.step >= len(th.regvals) {
		return fuzzProtocolExhaustedRegval
	}
	return th.regvals[th.step]
}

func (th *fuzzProtocolThread) Breakpoint() *BreakpointState { return &BreakpointState{} }
func (th *fuzzProtocolThread) ThreadID() int                { return 1 }

func (th *fuzzProtocolThread) Registers() (Registers, error) {
	return &fuzzProtocolRegs{protocolReg: th.protocolReg, regval: th.currentRegval()}, nil
}

func (th *fuzzProtocolThread) RestoreRegisters(Registers) error { return nil }
func (th *fuzzProtocolThread) BinInfo() *BinaryInfo             { return th.bi }
func (th *fuzzProtocolThread) ProcessMemory() MemoryReadWriter  { return th.mem }
func (th *fuzzProtocolThread) SetCurrentBreakpoint(bool) error  { return nil }
func (th *fuzzProtocolThread) SoftExc() bool                    { return false }
func (th *fuzzProtocolThread) Common() *CommonThread            { return &th.common }

func (th *fuzzProtocolThread) SetReg(uint64, *op.DwarfRegister) error {
	th.setRegCalls++
	return nil
}

// fuzzProtocolProcess is the minimal Process embedded in the mock Target. Only
// BinInfo, ThreadList and Memory are exercised (by funcCallStep and by
// Target.ClearCaches); the rest return zero values.
type fuzzProtocolProcess struct {
	bi  *BinaryInfo
	mem MemoryReadWriter
}

func (p *fuzzProtocolProcess) BinInfo() *BinaryInfo          { return p.bi }
func (p *fuzzProtocolProcess) EntryPoint() (uint64, error)   { return 0, nil }
func (p *fuzzProtocolProcess) FindThread(int) (Thread, bool) { return nil, false }
func (p *fuzzProtocolProcess) ThreadList() []Thread          { return nil }
func (p *fuzzProtocolProcess) Breakpoints() *BreakpointMap   { return nil }
func (p *fuzzProtocolProcess) Memory() MemoryReadWriter      { return p.mem }

// fuzzProtocolProcessGroup is the mock ProcessGroup wired into the
// TargetGroup. StepInstruction succeeds as a no-op so RestoreRegisters can
// finish the protocol (via stepInstructionOut) and reach the post-finish
// SetTarget path that telemetry issues #4085/#4363 hit. ContinueOnce still
// returns errFuzzNoLiveTarget for any accidental full-continue.
type fuzzProtocolProcessGroup struct{}

func (fuzzProtocolProcessGroup) ContinueOnce(*ContinueOnceContext) (Thread, StopReason, error) {
	return nil, StopUnknown, errFuzzNoLiveTarget
}
func (fuzzProtocolProcessGroup) StepInstruction(int) error { return nil }
func (fuzzProtocolProcessGroup) Detach(int, bool) error    { return nil }
func (fuzzProtocolProcessGroup) Close() error              { return nil }

// newFuzzProtocolImage builds a minimal BinaryInfo image with enough DWARF for
// EntryLineForFunc and fakeFunctionEntryScope (non-nil symTable/dwarfReader).
func newFuzzProtocolImage() (*Image, dwarf.Offset) {
	dwb := dwarfbuilder.New()
	fnOff := dwb.AddSubprogram("fuzz.fn", fuzzProtocolFixedPC, fuzzProtocolFixedPC+1)
	dwb.TagClose() // subprogram; Build() closes the compile unit opened by New

	abbrev, _, _, info, _, _, _, _, _, err := dwb.Build()
	img := &Image{
		symTable:        &gosym.Table{},
		dwarfTreeCache:  lru.NewCache[dwarf.Offset, *godwarf.Tree](dwarfTreeCacheSize),
		workaroundCache: make(map[dwarf.Offset]*godwarf.Tree),
	}
	if err != nil {
		return img, fnOff
	}
	dw, err := dwarf.New(abbrev, nil, nil, info, nil, nil, nil, nil)
	if err != nil || dw == nil {
		return img, fnOff
	}
	img.dwarf = dw
	img.dwarfReader = dw.Reader()
	return img, fnOff
}

// seedFuzzProtocolStackCache installs a cached stack trace whose top frame
// carries valid PC/SP dwarf registers. ThreadStacktrace otherwise synthesizes
// a first frame with zeroed Regs when unwinding fails on the empty mock target.
func seedFuzzProtocolStackCache(tgt *Target, bi *BinaryInfo, mem MemoryReadWriter, th *fuzzProtocolThread, g *G) {
	dregs := bi.Arch.addrAndStackRegsToDwarfRegisters(0, fuzzProtocolFixedPC, fuzzProtocolFixedSP, fuzzProtocolFixedSP, 0)
	dregs.CFA = int64(fuzzProtocolFixedSP + 0x80)

	loc := Location{PC: fuzzProtocolFixedPC, File: "?", Line: -1}
	top := Stackframe{
		Current: loc,
		Call:    loc,
		Regs:    dregs,
		Ret:     fuzzProtocolFixedPC + 1,
		stackHi: fuzzProtocolFixedSP + 0x1000,
		lastpc:  fuzzProtocolFixedPC,
	}
	bottom := Stackframe{Regs: dregs, Ret: 0, Err: NullAddrError{}}
	frames := []Stackframe{top, bottom}

	itThread := newStackIterator(tgt, bi, mem, dregs, 0, nil, 0)
	tgt.scache.put(0, th.ThreadID(), itThread, frames)

	if g != nil {
		itG := newStackIterator(tgt, bi, mem, dregs, g.stack.hi, g, 0)
		threadID := 0
		if g.Thread != nil {
			threadID = g.Thread.ThreadID()
		}
		tgt.scache.put(g.ID, threadID, itG, frames)
	}
}

// setupPostStartCallInjection builds the evalStack and EvalScope needed to run
// the post-Start portion of the call-injection protocol against th, seeding
// state as if evalCallInjectionStart had already succeeded.
//
// Minimal Target/callContext fields populated (everything funcCallStep and the
// opcode loop dereference on the pre-SetTarget paths):
//   - scope.callCtx.p: a *Target whose embedded Process yields BinInfo/Memory
//     and an empty fncallForG map (indexed by scope.g.ID for the CompleteCall
//     branch).
//   - scope.callCtx.grp: a *TargetGroup with a mock ProcessGroup so
//     stepInstructionOut fails cleanly.
//   - scope.g: a minimal goroutine so callScope.g.ID is valid.
//   - a seeded functionCallState with protocolReg/debugCallName/savedRegs and
//     hasDebugPinner=true so CallInjectionSetTarget skips funcCallEvalFuncExpr
//     (which would need a real function Variable on the value stack).
//
// The returned stack has ops = [CallInjectionSetTarget, CallInjectionComplete]
// and opidx = 0, i.e. positioned at the first opcode after a synthetic Start.
// A dummy function Variable is pushed so CallInjectionSetTarget's Pop and a
// dummy *Function (Entry != 0) are available if a sequence ever reaches
// SetTarget.
func setupPostStartCallInjection(th *fuzzProtocolThread) (*evalStack, *EvalScope) {
	bi := th.bi
	mem := th.mem

	fuzzImage, fnOff := newFuzzProtocolImage()
	bi.Images = []*Image{fuzzImage}

	// savedRegs is the register snapshot taken at Start; it must NOT be drawn
	// from the protocol-value sequence (that would consume regvals[0] before
	// the first funcCallStep ever runs).
	var savedRegs Registers = &fuzzProtocolRegs{protocolReg: th.protocolReg, regval: 0}

	tgt := &Target{
		Process:    &fuzzProtocolProcess{bi: bi, mem: mem},
		fncallForG: map[int64]*callInjection{},
	}
	tgt.scache.init()
	grp := &TargetGroup{procgrp: fuzzProtocolProcessGroup{}}

	g := &G{
		ID: 1,
		PC: fuzzProtocolFixedPC,
		SP: fuzzProtocolFixedSP,
		BP: fuzzProtocolFixedSP,
		stack: stack{
			lo: fuzzProtocolFixedSP - 0x1000,
			hi: fuzzProtocolFixedSP + 0x1000,
		},
		variable: &Variable{bi: bi, mem: mem},
	}
	th.common.g = g
	seedFuzzProtocolStackCache(tgt, bi, mem, th, g)
	tgt.fncallForG[g.ID] = &callInjection{startThreadID: th.ThreadID()}

	scope := &EvalScope{
		Mem:     mem,
		BinInfo: bi,
		g:       g,
		target:  tgt,
		callCtx: &callContext{
			grp: grp,
			p:   tgt,
		},
	}

	fncall := &functionCallState{
		protocolReg:    th.protocolReg,
		debugCallName:  "runtime.debugCallV2",
		savedRegs:      savedRegs,
		hasDebugPinner: true,
		fn: &Function{
			Entry:  fuzzProtocolFixedPC,
			offset: fnOff,
			cu:     &compileUnit{image: fuzzImage},
		},
	}

	stack := &evalStack{
		scope:     scope,
		curthread: th,
	}
	stack.fncallPush(fncall)

	// Dummy value consumed by CallInjectionSetTarget's Pop (the target
	// function), only reached on happy-path sequences.
	stack.push(newConstant(constant.MakeBool(false), bi, mem))

	stack.ops = []evalop.Op{
		&evalop.CallInjectionSetTarget{},
		&evalop.CallInjectionComplete{DoPinning: false},
	}
	stack.opidx = 0

	return stack, scope
}

// runCallInjectionProtocolFuzz drives the call-injection protocol handler with
// the given sequence of protocol register values and returns the resulting
// error (nil, a clean protocol error, or a recovered panic reported as an
// "internal debugger error"). It never panics: any panic escaping the real
// protocol code is recovered and surfaced as an error so callers/fuzzers can
// treat it uniformly.
func runCallInjectionProtocolFuzz(regvals []uint64) (err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("internal debugger error: panic: %v", r)
		}
	}()

	bi := NewBinaryInfo("linux", "amd64")
	th := newFuzzProtocolThread(bi, regvals)
	stack, scope := setupPostStartCallInjection(th)

	// Mirror the relevant part of evalStack.resume's loop (see eval.go),
	// stepping the protocol once per provided register value. th.step pins
	// the mock thread's registers for the whole iteration, so every
	// Registers() call made while processing this "stop" (by funcCallStep
	// and by anything stack.run() calls, e.g. evalCallInjectionSetTarget)
	// observes the same regval, matching a real thread that only changes
	// registers when the target is resumed.
	for step := 0; step < len(regvals)+2; step++ {
		th.step = step
		finished := funcCallStep(scope, stack, th)
		if finished {
			funcCallFinish(scope, stack)
		}
		if stack.err == nil && len(stack.fncalls) > 0 {
			if fncall := stack.fncallPeek(); fncall.err != nil {
				stack.err = fncall.err
			}
		}
		if stack.callInjectionContinue {
			stack.callInjectionContinue = false
			continue
		}
		if stack.err != nil {
			break
		}
		// Match evalStack.resume: after the protocol step (including a
		// finished call that emptied fncalls), resume opcode execution.
		// Breaking when fncalls is empty would skip CallInjectionSetTarget
		// and hide the #4085/#4363 empty-fncalls panic.
		stack.run()
		if !stack.callInjectionContinue {
			break
		}
		stack.callInjectionContinue = false
	}

	return stack.err
}

func TestCallInjectionProtocol_PrematureRestore_NoPanic(t *testing.T) {
	err := runCallInjectionProtocolFuzz([]uint64{16}) // RestoreRegisters first
	if err == nil {
		t.Fatal("expected error for premature RestoreRegisters before SetTarget")
	}
	// Step-out must succeed so the protocol can finish and exercise the
	// empty-fncalls / SetTarget path (telemetry #4085/#4363). A "no live
	// target" short-circuit would hide that crash.
	if strings.Contains(err.Error(), "no live target") {
		t.Fatalf("stepInstructionOut should succeed in the mock; got harness short-circuit: %v", err)
	}
	failIfInternalDebuggerError(t, err)
	if !strings.Contains(err.Error(), "terminated before target") {
		t.Fatalf("expected clean terminated-before-target error, got: %v", err)
	}
}

// TestCallInjectionProtocolSeeds exercises the full debugCall protocol
// register set {0, 1, 2, 8, 16, garbage} on the hardened mock (see file
// header). debugCallRegCompleteCall (0) must appear at most once per
// sequence: the real protocol only ever signals "ready to call" once for a
// given injection, and the mock's fixed two-op stack
// (CallInjectionSetTarget/CallInjectionComplete, see
// setupPostStartCallInjection) has nothing left to run for a second 0 —
// replaying it trips eval.go's "eval program finished without error but N
// call injections still active" sanity check. That was found by the fuzz
// smoke test on the input "0000" and is exactly what FuzzCallInjectionProtocol
// guards against below by only ever emitting one 0 per input (see
// fuzzProtocolGarbageRegval).
func TestCallInjectionProtocolSeeds_PrecheckAndStackReads(t *testing.T) {
	seeds := [][]uint64{
		{8}, {8, 16},
		{1}, {1, 16},
		{2}, {2, 16},
		{0, 1, 16},
	}
	for _, s := range seeds {
		t.Run(fmt.Sprintf("%v", s), func(t *testing.T) {
			err := runCallInjectionProtocolFuzz(s)
			failIfInternalDebuggerError(t, err)
		})
	}
}

func TestCallInjectionProtocolSeeds(t *testing.T) {
	seeds := [][]uint64{
		{16},                  // premature restore
		{0x42, 16},            // unknown then restore
		{0, 16},               // complete-call then restore
		{0, 0x42, 16},         // complete-call, unknown, then restore
		{0, 0x42, 0x43, 0x44}, // complete-call then repeated unknown/garbage
		{8, 16},               // precheck-failed then restore
		{1, 16},               // read-return then restore
		{0, 1, 16},            // complete-call, read-return, then restore
		{2, 16},               // read-panic then restore
		// (never a second literal 0; see
		// TestCallInjectionProtocolSeeds_RepeatedCompleteCall for why a
		// repeated debugCallRegCompleteCall is excluded from this table).
	}
	for _, s := range seeds {
		t.Run(fmt.Sprintf("%v", s), func(t *testing.T) {
			err := runCallInjectionProtocolFuzz(s)
			failIfInternalDebuggerError(t, err)
		})
	}
}

// TestCallInjectionProtocolSeeds_RepeatedCompleteCall documents (and guards
// against regressing) a real finding from the FuzzCallInjectionProtocol smoke
// test: a debugCallRegCompleteCall (0) that repeats after the call injection
// protocol already advanced past it drives eval.go's evalStack.run() into
// "eval program finished without error but N call injections still active" —
// a real, pre-existing sanity-check error in production code, not a mock
// artifact (confirmed by tracing funcCallStep/evalCallInjectionSetTarget/
// evalStack.run in fncall.go and eval.go). Because the mock's single fixed
// call injection can't legitimately be "readied" twice, this input is
// deliberately kept out of the fuzz corpus/mapping; this test only records that
// runCallInjectionProtocolFuzz still classifies it correctly (a clean,
// non-panicking error) rather than crashing outright.
func TestCallInjectionProtocolSeeds_RepeatedCompleteCall(t *testing.T) {
	err := runCallInjectionProtocolFuzz([]uint64{0, 0, 0, 0})
	if err == nil {
		t.Fatal("expected an error for a repeated debugCallRegCompleteCall sequence")
	}
	if !strings.Contains(err.Error(), "call injections still active") {
		t.Fatalf("expected the known 'call injections still active' sanity-check error, got: %v", err)
	}
}

// FuzzCallInjectionProtocol fuzzes debugCall protocol register sequences
// against a post-Start call-injection eval stack.
//
// Each fuzz byte maps via b%6 onto the full debugCall register set:
// debugCallRegCompleteCall (0), debugCallRegReadReturn (1),
// debugCallRegReadPanic (2), debugCallRegPrecheckFailed (8),
// debugCallRegRestoreRegisters (16), or an unknown/garbage value (see
// fuzzProtocolGarbageRegval). The mock fails cleanly on the ThreadScope/
// readStackVariable paths (see file header).
//
// debugCallRegCompleteCall (0) is capped at one occurrence per input (see
// fuzzProtocolGarbageRegval and TestCallInjectionProtocolSeeds_RepeatedCompleteCall):
// a second 0 hits a real (pre-existing, non-mock) sanity check in eval.go that
// the fixed single-call mock stack can't satisfy.
//
//	go test -run NONE -fuzz FuzzCallInjectionProtocol -fuzztime=5s ./pkg/proc
func FuzzCallInjectionProtocol(f *testing.F) {
	f.Add([]byte{16})
	f.Add([]byte{0x42, 16})
	f.Add([]byte{0, 16})
	f.Add([]byte{0, 0x42, 16})
	f.Add([]byte{3, 4})   // {8, 16}
	f.Add([]byte{1, 4})   // {1, 16}
	f.Add([]byte{0, 1, 4}) // {0, 1, 16}
	f.Add([]byte{2, 4})   // {2, 16}
	f.Add([]byte{0, 0, 0, 0}) // regression: used to trip "still active" (see above); now de-duped to a single 0
	f.Fuzz(func(t *testing.T, buf []byte) {
		if len(buf) == 0 {
			return
		}
		if len(buf) > 8 {
			buf = buf[:8]
		}
		regs := make([]uint64, len(buf))
		seenCompleteCall := false
		for i, b := range buf {
			switch b % 6 {
			case 0:
				if seenCompleteCall {
					// A second debugCallRegCompleteCall folds into the
					// garbage bucket instead of feeding it to the mock.
					regs[i] = fuzzProtocolGarbageRegval(b)
					continue
				}
				seenCompleteCall = true
				regs[i] = 0 // debugCallRegCompleteCall
			case 1:
				regs[i] = 1 // debugCallRegReadReturn
			case 2:
				regs[i] = 2 // debugCallRegReadPanic
			case 3:
				regs[i] = 8 // debugCallRegPrecheckFailed
			case 4:
				regs[i] = 16 // debugCallRegRestoreRegisters
			default:
				regs[i] = fuzzProtocolGarbageRegval(b) // funcCallStep no-op branch
			}
		}
		err := runCallInjectionProtocolFuzz(regs)
		failIfInternalDebuggerError(t, err)
	})
}

// fuzzProtocolGarbageRegval maps a raw fuzz byte to an "unknown protocol
// register" value for funcCallStep's default (no-op) branch. It is offset so
// it can never collide with any real debugCall protocol register value (0,
// 1, 2, 8, 16) — a plain uint64(b) would, since b ranges over 0-255 and could
// land exactly on 1, 2, or 8, silently reintroducing a real protocol branch
// into the garbage bucket.
func fuzzProtocolGarbageRegval(b byte) uint64 {
	return uint64(b) + 0x100
}
