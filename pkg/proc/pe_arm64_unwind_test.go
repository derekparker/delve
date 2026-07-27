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
