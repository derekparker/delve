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

func TestDecodeARM64UnwindCodes_AllocM(t *testing.T) {
	// alloc_m n=3 → 48 bytes, end
	codes := []byte{0xc8, 0x03, 0xe4}
	fctxt, ok := decodeARM64UnwindCodes(codes)
	if !ok {
		t.Fatal("expected decode success")
	}
	if fctxt.CFA.Offset != 48 {
		t.Fatalf("CFA offset=%d want 48", fctxt.CFA.Offset)
	}
}

func TestDecodeARM64UnwindCodes_SaveFplr(t *testing.T) {
	// save_fplr z=2 at [sp+16], alloc_s 32, end
	codes := []byte{0x42, 0x02, 0xe4}
	fctxt, ok := decodeARM64UnwindCodes(codes)
	if !ok {
		t.Fatal("expected decode success")
	}
	if fctxt.CFA.Offset != 32 {
		t.Fatalf("CFA offset=%d want 32", fctxt.CFA.Offset)
	}
	bp := fctxt.Regs[regnum.ARM64_BP]
	if bp.Rule != frame.RuleOffset || bp.Offset != -16 {
		t.Fatalf("BP rule=%+v want Offset -16", bp)
	}
	lr := fctxt.Regs[regnum.ARM64_LR]
	if lr.Rule != frame.RuleOffset || lr.Offset != -8 {
		t.Fatalf("LR rule=%+v want Offset -8", lr)
	}
}

func TestDecodeARM64UnwindCodes_SaveRegX(t *testing.T) {
	// save_reg_x x19 pre-index 8 bytes, end
	codes := []byte{0xd4, 0x00, 0xe4}
	fctxt, ok := decodeARM64UnwindCodes(codes)
	if !ok {
		t.Fatal("expected decode success")
	}
	if fctxt.CFA.Offset != 8 {
		t.Fatalf("CFA offset=%d want 8", fctxt.CFA.Offset)
	}
	x19 := fctxt.Regs[regnum.ARM64_X0+19]
	if x19.Rule != frame.RuleOffset || x19.Offset != -8 {
		t.Fatalf("x19 rule=%+v want Offset -8", x19)
	}
}

func TestDecodeARM64UnwindCodes_AddFp(t *testing.T) {
	// alloc_s 16, add_fp (ignored for body-only CFA), end
	codes := []byte{0x01, 0xe2, 0x00, 0xe4}
	fctxt, ok := decodeARM64UnwindCodes(codes)
	if !ok {
		t.Fatal("expected decode success")
	}
	if fctxt.CFA.Offset != 16 {
		t.Fatalf("CFA offset=%d want 16", fctxt.CFA.Offset)
	}
}

func TestDecodeARM64UnwindCodes_UnsupportedOpcode(t *testing.T) {
	if _, ok := decodeARM64UnwindCodes([]byte{0xe3, 0xe4}); ok {
		t.Fatal("expected decode failure for nop opcode")
	}
}

func TestDecodeARM64UnwindCodes_TruncatedMultiByte(t *testing.T) {
	cases := [][]byte{
		{0xc8}, // alloc_m missing operand
		{0xe2}, // add_fp missing operand
		{0xd4}, // save_reg_x missing operand
		{0xd0}, // save_reg missing operand
	}
	for _, codes := range cases {
		if _, ok := decodeARM64UnwindCodes(codes); ok {
			t.Fatalf("expected decode failure for truncated stream % x", codes)
		}
	}
}

func TestDecodeARM64UnwindCodes_UnterminatedStream(t *testing.T) {
	cases := [][]byte{
		{0x02},             // alloc_s without end
		{0x02, 0x01},       // alloc_s + alloc_s without end
		{0x42, 0x02},       // save_fplr + alloc_s without end
	}
	for _, codes := range cases {
		if _, ok := decodeARM64UnwindCodes(codes); ok {
			t.Fatalf("expected decode failure for unterminated stream % x", codes)
		}
	}
}
