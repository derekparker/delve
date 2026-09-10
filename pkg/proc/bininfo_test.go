package proc

import (
	"reflect"
	"testing"

	"github.com/go-delve/delve/pkg/internal/gosym"
)

func TestAddPCLNFunctionsMergesUniqueFunctions(t *testing.T) {
	tests := []struct {
		name          string
		dwarfFunction Function
		pclnFunction  gosym.Func
		want          []Function
	}{
		{
			name:          "same entry different name",
			dwarfFunction: Function{Name: "main.main", Entry: 0x1000, End: 0x1020},
			pclnFunction:  pclnFunction("main.main.abi0", 0x1000, 0x1020),
			want:          []Function{{Name: "main.main", Entry: 0x1000, End: 0x1020}},
		},
		{
			name:          "same name different entry",
			dwarfFunction: Function{Name: "main.main", Entry: 0x1000, End: 0x1020},
			pclnFunction:  pclnFunction("main.main", 0x1010, 0x1020),
			want:          []Function{{Name: "main.main", Entry: 0x1000, End: 0x1020}},
		},
		{
			name:          "new function",
			dwarfFunction: Function{Name: "main.main", Entry: 0x1000, End: 0x1020},
			pclnFunction:  pclnFunction("main.call+0-tramp0", 0x1010, 0x1020),
			want: []Function{
				{Name: "main.main", Entry: 0x1000, End: 0x1020},
				{Name: "main.call+0-tramp0", Entry: 0x1010, End: 0x1020},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			image := &Image{symTable: &gosym.Table{Funcs: []gosym.Func{test.pclnFunction}}}
			test.dwarfFunction.cu = &compileUnit{image: image}
			bi := &BinaryInfo{Functions: []Function{test.dwarfFunction}}

			bi.addPCLNFunctions(image)

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
