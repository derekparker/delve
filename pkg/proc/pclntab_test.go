package proc

import (
	"debug/elf"
	"testing"
)

func TestELFTextBase(t *testing.T) {
	const (
		sectionText = 0x401000
		runtimeText = 0x40110e
	)
	tests := []struct {
		name    string
		symbols []elf.Symbol
		want    uint64
	}{
		{
			name: "runtime.text symbol",
			symbols: []elf.Symbol{
				{Name: "main.main", Value: 0x49a6c0},
				{Name: "runtime.text", Value: runtimeText},
			},
			want: runtimeText,
		},
		{
			name:    "section address fallback",
			symbols: []elf.Symbol{{Name: "main.main", Value: 0x49a6c0}},
			want:    sectionText,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := elfTextBase(test.symbols, sectionText); got != test.want {
				t.Fatalf("got text base %#x, want %#x", got, test.want)
			}
		})
	}
}
