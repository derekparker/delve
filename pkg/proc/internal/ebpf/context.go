package ebpf

import (
	"reflect"

	"github.com/go-delve/delve/pkg/dwarf/godwarf"
	"github.com/go-delve/delve/pkg/dwarf/op"
)

type UProbeArgMap struct {
	Offset      int64        // Offset from the stackpointer.
	Size        int64        // Size in bytes.
	Kind        reflect.Kind // Kind of variable.
	ElementSize int64        // For slices/arrays: size of each element. Zero for non-slice types.
	Pieces      []int        // Pieces of the variables as stored in registers.
	InReg       bool         // True if this param is contained in a register.
	Ret         bool         // True if this param is a return value.
}

type RawUProbeParam struct {
	Pieces      []op.Piece
	RealType    godwarf.Type
	Kind        reflect.Kind
	Len         int64
	Cap         int64
	Base        uint64
	Addr        uint64
	Data        []byte
	ElementSize int64 // For slices/arrays: size of each element
}

type RawUProbeParams struct {
	FnAddr       int
	GoroutineID  int
	IsRet        bool
	InputParams  []*RawUProbeParam
	ReturnParams []*RawUProbeParam
}
