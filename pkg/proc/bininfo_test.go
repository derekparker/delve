package proc

import (
	"reflect"
	"testing"

	"github.com/go-delve/delve/pkg/internal/gosym"
)

func TestAddPCLNTrampolineFunctionsMergesUniqueFunctions(t *testing.T) {
	tests := []struct {
		name           string
		dwarfFunctions []Function
		pclnFunction   gosym.Func
		want           []Function
	}{
		{
			name:           "same entry different name",
			dwarfFunctions: []Function{{Name: "main.main", Entry: 0x1000, End: 0x1020}},
			pclnFunction:   pclnFunction("main.call+0-tramp0", 0x1000, 0x1020),
			want:           []Function{{Name: "main.main", Entry: 0x1000, End: 0x1020}},
		},
		{
			name:           "same name different entry",
			dwarfFunctions: []Function{{Name: "main.call+0-tramp0", Entry: 0x1000, End: 0x1020}},
			pclnFunction:   pclnFunction("main.call+0-tramp0", 0x1020, 0x1040),
			want:           []Function{{Name: "main.call+0-tramp0", Entry: 0x1000, End: 0x1020}},
		},
		{
			name:           "new function",
			dwarfFunctions: []Function{{Name: "main.main", Entry: 0x1000, End: 0x1020}},
			pclnFunction:   pclnFunction("main.call+0-tramp0", 0x1020, 0x1040),
			want: []Function{
				{Name: "main.main", Entry: 0x1000, End: 0x1020},
				{Name: "main.call+0-tramp0", Entry: 0x1020, End: 0x1040},
			},
		},
		{
			name:           "non-trampoline pclntab-only function",
			dwarfFunctions: []Function{{Name: "main.main", Entry: 0x1000, End: 0x1020}},
			pclnFunction:   pclnFunction("runtime.asmcgocall", 0x1020, 0x1040),
			want:           []Function{{Name: "main.main", Entry: 0x1000, End: 0x1020}},
		},
		{
			name:           "new function overlapping next DWARF range",
			dwarfFunctions: []Function{{Name: "__x86.get_pc_thunk.cx", Entry: 0x1010, End: 0x1014}},
			pclnFunction:   pclnFunction("runtime.main+0-tramp0", 0x1000, 0x1020),
			want:           []Function{{Name: "__x86.get_pc_thunk.cx", Entry: 0x1010, End: 0x1014}},
		},
		{
			name: "new function overlapping non-adjacent previous DWARF range",
			dwarfFunctions: []Function{
				{Name: "runtime.main", Entry: 0x1000, End: 0x1100},
				{Name: "__x86.get_pc_thunk.cx", Entry: 0x1010, End: 0x1014},
			},
			pclnFunction: pclnFunction("runtime.main.func2+0-tramp0", 0x1020, 0x1040),
			want: []Function{
				{Name: "runtime.main", Entry: 0x1000, End: 0x1100},
				{Name: "__x86.get_pc_thunk.cx", Entry: 0x1010, End: 0x1014},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			image := &Image{symTable: &gosym.Table{Funcs: []gosym.Func{test.pclnFunction}}}
			for i := range test.dwarfFunctions {
				test.dwarfFunctions[i].cu = &compileUnit{image: image}
			}
			bi := &BinaryInfo{Functions: test.dwarfFunctions}

			bi.addPCLNTrampolineFunctions(image)

			for i := range bi.Functions {
				bi.Functions[i].cu = nil
			}
			if !reflect.DeepEqual(bi.Functions, test.want) {
				t.Fatalf("got functions %#v, want %#v", bi.Functions, test.want)
			}
		})
	}
}

func pclnFunction(name string, entry, end uint64) gosym.Func {
	return gosym.Func{
		Entry: entry,
		End:   end,
		Sym:   &gosym.Sym{Name: name},
	}
}
