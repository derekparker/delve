package proc

import (
	"encoding/binary"
	"testing"

	"github.com/go-delve/delve/pkg/dwarf/frame"
	"github.com/go-delve/delve/pkg/dwarf/regnum"
)

// Unwind bytes from clang aarch64-windows: save_reg lr@[sp+16], alloc_s 32, end.
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

func TestDecodeARM64UnwindCodes_IgnoresPaddingAfterEnd(t *testing.T) {
	// alloc_s 32, end, then trailing padding byte must not inflate CFA.
	codes := []byte{0x02, 0xe4, 0x02}
	fctxt, ok := decodeARM64UnwindCodes(codes)
	if !ok {
		t.Fatal("expected decode success")
	}
	if fctxt.CFA.Offset != 32 {
		t.Fatalf("CFA offset=%d want 32", fctxt.CFA.Offset)
	}
}

func TestPEARM64Unwind_SkipsPackedPdataEntry(t *testing.T) {
	imageBase := uint64(0x100000000)
	// Valid xdata at offset 0; byte 0 is padding so the same record also parses at offset 1.
	xdata := []byte{0x00, 0x09, 0x00, 0x20, 0x08, 0xd2, 0xc2, 0x02, 0xe4}
	pdata := make([]byte, 8)
	binary.LittleEndian.PutUint32(pdata[0:], 0x1000)
	// Flag=1 (packed): old bit-31 parsing treats xdata RVA as 1 and would index this entry.
	binary.LittleEndian.PutUint32(pdata[4:], 1)
	u := buildPEARM64Unwind(pdata, xdata, imageBase, 0)
	if u == nil {
		t.Fatal("nil unwind")
	}
	if len(u.entries) != 0 {
		t.Fatalf("entries=%d want 0 for packed pdata", len(u.entries))
	}
	if _, ok := u.FrameContextForPC(imageBase + 0x1000 + 8); ok {
		t.Fatal("expected miss for packed pdata entry")
	}
}

func TestPEARM64Unwind_FrameContextForPC(t *testing.T) {
	imageBase := uint64(0x100000000)
	// One pdata entry: begin RVA 0x1000, xdata at RVA 0 — store xdata as section starting at 0 for test
	xdata := []byte{0x09, 0x00, 0x20, 0x08, 0xd2, 0xc2, 0x02, 0xe4}
	// pdata: begin=0x1000, info=0 (xdata RVA 0, flag 0)
	pdata := make([]byte, 8)
	binary.LittleEndian.PutUint32(pdata[0:], 0x1000)
	binary.LittleEndian.PutUint32(pdata[4:], 0) // flag 0, xdata RVA 0
	u := buildPEARM64Unwind(pdata, xdata, imageBase, 0)
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

func TestPEARM64Unwind_FrameContextForPC_NonZeroXdataSectionRVA(t *testing.T) {
	imageBase := uint64(0x100000000)
	const xdataSectionRVA = uint32(0x2000)
	clangRecord := []byte{0x09, 0x00, 0x20, 0x08, 0xd2, 0xc2, 0x02, 0xe4}

	t.Run("record at section base", func(t *testing.T) {
		pdata := make([]byte, 8)
		binary.LittleEndian.PutUint32(pdata[0:], 0x1000)
		binary.LittleEndian.PutUint32(pdata[4:], xdataSectionRVA) // xdata RVA 0x2000, flag 0
		u := buildPEARM64Unwind(pdata, clangRecord, imageBase, xdataSectionRVA)
		if u == nil {
			t.Fatal("nil unwind")
		}
		if len(u.entries) != 1 {
			t.Fatalf("entries=%d want 1", len(u.entries))
		}
		if u.entries[0].xdataOff != 0 {
			t.Fatalf("xdataOff=%d want 0", u.entries[0].xdataOff)
		}
		fctxt, ok := u.FrameContextForPC(imageBase + 0x1000 + 8)
		if !ok || fctxt == nil {
			t.Fatal("expected hit")
		}
		if fctxt.CFA.Offset != 32 {
			t.Fatalf("CFA offset=%d want 32", fctxt.CFA.Offset)
		}
	})

	t.Run("record after padding in section buffer", func(t *testing.T) {
		xdata := make([]byte, 8+len(clangRecord))
		copy(xdata[8:], clangRecord)
		pdata := make([]byte, 8)
		binary.LittleEndian.PutUint32(pdata[0:], 0x1000)
		binary.LittleEndian.PutUint32(pdata[4:], xdataSectionRVA+8) // xdata RVA 0x2008, flag 0
		u := buildPEARM64Unwind(pdata, xdata, imageBase, xdataSectionRVA)
		if u == nil {
			t.Fatal("nil unwind")
		}
		if len(u.entries) != 1 {
			t.Fatalf("entries=%d want 1", len(u.entries))
		}
		if u.entries[0].xdataOff != 8 {
			t.Fatalf("xdataOff=%d want 8", u.entries[0].xdataOff)
		}
		fctxt, ok := u.FrameContextForPC(imageBase + 0x1000 + 8)
		if !ok || fctxt == nil {
			t.Fatal("expected hit")
		}
		if fctxt.CFA.Offset != 32 {
			t.Fatalf("CFA offset=%d want 32", fctxt.CFA.Offset)
		}
	})
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
