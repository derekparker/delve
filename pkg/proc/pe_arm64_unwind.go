package proc

import (
	"encoding/binary"
	"sort"

	"github.com/go-delve/delve/pkg/dwarf/frame"
	"github.com/go-delve/delve/pkg/dwarf/regnum"
)

type peARM64PdataEntry struct {
	begin, end uint64
	xdataOff   uint32
	packed     uint32
	isPacked   bool
}

type peARM64Unwind struct {
	entries   []peARM64PdataEntry
	xdata     []byte
	imageBase uint64
}

func buildPEARM64Unwind(pdata, xdata []byte, imageBase uint64) *peARM64Unwind {
	u := &peARM64Unwind{
		xdata:     xdata,
		imageBase: imageBase,
	}
	const xdataSectionRVA = uint32(0)
	for off := 0; off+8 <= len(pdata); off += 8 {
		beginRVA := binary.LittleEndian.Uint32(pdata[off:])
		info := binary.LittleEndian.Uint32(pdata[off+4:])
		flag := info & 0x3
		if flag != 0 {
			continue
		}
		xdataRVA := info &^ 0x3
		xdataOff := xdataRVA - xdataSectionRVA
		if int(xdataOff) >= len(xdata) {
			continue
		}
		funcLen, _, ok := parseARM64Xdata(xdata[xdataOff:])
		if !ok {
			continue
		}
		begin := imageBase + uint64(beginRVA)
		u.entries = append(u.entries, peARM64PdataEntry{
			begin:    begin,
			end:      begin + uint64(funcLen),
			xdataOff: xdataOff,
		})
	}
	sort.Slice(u.entries, func(i, j int) bool {
		return u.entries[i].begin < u.entries[j].begin
	})
	return u
}

func (u *peARM64Unwind) FrameContextForPC(pc uint64) (*frame.FrameContext, bool) {
	if u == nil || len(u.entries) == 0 {
		return nil, false
	}
	i := sort.Search(len(u.entries), func(i int) bool {
		return u.entries[i].begin > pc
	}) - 1
	if i < 0 {
		return nil, false
	}
	e := u.entries[i]
	if pc >= e.end {
		return nil, false
	}
	if e.isPacked {
		return nil, false
	}
	if int(e.xdataOff) >= len(u.xdata) {
		return nil, false
	}
	_, codes, ok := parseARM64Xdata(u.xdata[e.xdataOff:])
	if !ok {
		return nil, false
	}
	return decodeARM64UnwindCodes(codes)
}

func parseARM64Xdata(xdata []byte) (funcLen uint32, codes []byte, ok bool) {
	if len(xdata) < 4 {
		return 0, nil, false
	}
	word0 := binary.LittleEndian.Uint32(xdata[:4])

	funcLenField := word0 & 0x3ffff
	vers := (word0 >> 18) & 0x3
	if vers != 0 {
		return 0, nil, false
	}

	e := (word0 >> 21) & 1
	epilogCount := (word0 >> 22) & 0x1f
	codeWords := (word0 >> 27) & 0x1f

	if epilogCount == 0 && codeWords == 0 {
		return 0, nil, false
	}

	off := 4
	if e == 0 {
		off += int(epilogCount) * 4
	}

	codeBytes := int(codeWords) * 4
	if len(xdata) < off+codeBytes {
		return 0, nil, false
	}

	return funcLenField * 4, xdata[off : off+codeBytes], true
}

func decodeARM64UnwindCodes(codes []byte) (*frame.FrameContext, bool) {
	finalCFAOff, ok := arm64UnwindFinalCFAOffset(codes)
	if !ok {
		return nil, false
	}

	cfaOff := int64(0)
	regs := map[uint64]frame.DWRule{}
	sawEnd := false
	i := 0
	for i < len(codes) {
		op := codes[i]
		switch {
		case op == 0xe4: // end
			i++
			sawEnd = true
			goto done
		case op&0xe0 == 0x00: // alloc_s: 000xxxxx → size = xxxxx * 16
			cfaOff += int64(op&0x1f) * 16
			i++
		case op&0xc0 == 0x40: // save_fplr: 01zzzzzz
			z := int64(op & 0x3f)
			offFromCFA := -(finalCFAOff - z*8)
			regs[regnum.ARM64_BP] = frame.DWRule{Rule: frame.RuleOffset, Offset: offFromCFA}
			regs[regnum.ARM64_LR] = frame.DWRule{Rule: frame.RuleOffset, Offset: offFromCFA + 8}
			i++
		case op&0xc0 == 0x80: // save_fplr_x: 10zzzzzz — pre-index
			z := int64(op&0x3f) + 1
			cfaOff += z * 8
			regs[regnum.ARM64_BP] = frame.DWRule{Rule: frame.RuleOffset, Offset: -cfaOff}
			regs[regnum.ARM64_LR] = frame.DWRule{Rule: frame.RuleOffset, Offset: -cfaOff + 8}
			i++
		case op == 0xe1: // set_fp
			i++
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
			offFromCFA := -(finalCFAOff - z*8)
			regs[reg] = frame.DWRule{Rule: frame.RuleOffset, Offset: offFromCFA}
			i += 2
		case op&0xfe == 0xd4: // save_reg_x: 1101010x xxxzzzzz
			if i+1 >= len(codes) {
				return nil, false
			}
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
	if !sawEnd {
		return nil, false
	}
	if finalCFAOff == 0 && len(regs) == 0 {
		return nil, false
	}
	return &frame.FrameContext{
		RetAddrReg: regnum.ARM64_LR,
		CFA:        frame.DWRule{Rule: frame.RuleCFA, Reg: regnum.ARM64_SP, Offset: finalCFAOff},
		Regs:       regs,
	}, true
}

func arm64UnwindFinalCFAOffset(codes []byte) (int64, bool) {
	cfaOff := int64(0)
	i := 0
	for i < len(codes) {
		op := codes[i]
		switch {
		case op == 0xe4: // end
			return cfaOff, true
		case op == 0xe1: // set_fp
			i++
		case op&0xe0 == 0x00: // alloc_s
			cfaOff += int64(op&0x1f) * 16
			i++
		case op&0xc0 == 0x40: // save_fplr
			i++
		case op&0xc0 == 0x80: // save_fplr_x
			cfaOff += (int64(op&0x3f) + 1) * 8
			i++
		case op == 0xe2: // add_fp
			if i+1 >= len(codes) {
				return 0, false
			}
			i += 2
		case op&0xf8 == 0xc8: // alloc_m
			if i+1 >= len(codes) {
				return 0, false
			}
			n := (uint16(op&0x07) << 8) | uint16(codes[i+1])
			cfaOff += int64(n) * 16
			i += 2
		case op&0xfc == 0xd0: // save_reg
			if i+1 >= len(codes) {
				return 0, false
			}
			i += 2
		case op&0xfe == 0xd4: // save_reg_x
			if i+1 >= len(codes) {
				return 0, false
			}
			cfaOff += (int64(codes[i+1]&0x1f) + 1) * 8
			i += 2
		default:
			return 0, false
		}
	}
	return cfaOff, true
}
