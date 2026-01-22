//go:build linux && amd64 && cgo && go1.16

package ebpf

import (
	"reflect"
	"testing"
	"unsafe"

	"github.com/go-delve/delve/pkg/proc/internal/ebpf/testhelper"
)

func compareStructTypes(t *testing.T, gostructVal, cstructVal any) {
	gostruct := reflect.ValueOf(gostructVal).Type()
	cstruct := reflect.ValueOf(cstructVal).Type()
	if gostruct.NumField() != cstruct.NumField() {
		t.Errorf("mismatched field number %d %d", gostruct.NumField(), cstruct.NumField())
		return
	}
	for i := 0; i < cstruct.NumField(); i++ {
		gofield := gostruct.Field(i)
		cfield := cstruct.Field(i)
		t.Logf("%d %s %s\n", i, gofield.Name, cfield.Name)
		if gofield.Name != cfield.Name {
			t.Errorf("mismatched name for field %s %s", gofield.Name, cfield.Name)
		}
		if gofield.Offset != cfield.Offset {
			t.Errorf("mismatched offset for field %s %s (%d %d)", gofield.Name, cfield.Name, gofield.Offset, cfield.Offset)
		}
		if gofield.Type.Size() != cfield.Type.Size() {
			t.Errorf("mismatched size for field %s %s (%d %d)", gofield.Name, cfield.Name, gofield.Type.Size(), cfield.Type.Size())
		}
	}
}

func TestStructConsistency(t *testing.T) {
	t.Run("function_parameter_t", func(t *testing.T) {
		compareStructTypes(t, function_parameter_t{}, testhelper.Function_parameter_t{})
	})
	t.Run("function_parameter_list_t", func(t *testing.T) {
		compareStructTypes(t, function_parameter_list_t{}, testhelper.Function_parameter_list_t{})
	})
}

func TestParseSliceParam(t *testing.T) {
	// Create a mock function_parameter_list_t with a slice parameter
	var params function_parameter_list_t
	params.fn_addr = 0x1000
	params.goroutine_id = 1
	params.is_ret = false
	params.n_parameters = 1
	params.n_ret_parameters = 0

	// Set up a slice parameter: [ptr:8][len:8][cap:8]
	// ptr = 0x7fff00000000, len = 5, cap = 10
	sliceParam := &params.params[0]
	sliceParam.kind = uint32(reflect.Slice)
	sliceParam.size = 24 // 3 * 8 bytes

	// Write slice header into val field (little-endian)
	slicePtr := uint64(0x7fff00000000)
	sliceLen := uint64(5)
	sliceCap := uint64(10)

	for i := 0; i < 8; i++ {
		sliceParam.val[i] = byte(slicePtr >> (i * 8))
	}
	for i := 0; i < 8; i++ {
		sliceParam.val[8+i] = byte(sliceLen >> (i * 8))
	}
	for i := 0; i < 8; i++ {
		sliceParam.val[16+i] = byte(sliceCap >> (i * 8))
	}

	// Convert to bytes for parsing
	structSize := unsafe.Sizeof(params)
	rawBytes := (*[2048]byte)(unsafe.Pointer(&params))[:structSize]

	// Parse the parameter list
	result := parseFunctionParameterList(rawBytes)

	// Verify the results
	if len(result.InputParams) != 1 {
		t.Fatalf("expected 1 input param, got %d", len(result.InputParams))
	}

	param := result.InputParams[0]
	if param.Kind != reflect.Slice {
		t.Errorf("expected kind Slice, got %v", param.Kind)
	}

	if param.Base != slicePtr {
		t.Errorf("expected base 0x%x, got 0x%x", slicePtr, param.Base)
	}

	if param.Len != int64(sliceLen) {
		t.Errorf("expected len %d, got %d", sliceLen, param.Len)
	}

	if param.Cap != int64(sliceCap) {
		t.Errorf("expected cap %d, got %d", sliceCap, param.Cap)
	}
}
