//go:build linux && amd64 && go1.16

package ebpf

import (
	"context"
	"debug/elf"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"reflect"
	"sync"
	"time"
	"unsafe"

	"github.com/go-delve/delve/pkg/dwarf/godwarf"
	"github.com/go-delve/delve/pkg/dwarf/op"
	"github.com/go-delve/delve/pkg/logflags"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
)

//lint:file-ignore U1000 some fields are used by the C program

const (
	// fakeAddressUnresolv is the sentinel base address used for eBPF-captured
	// parameter values that live in a fake memory region. pkg/proc uses this
	// same value (via its own fakeAddressUnresolv constant) for composite
	// memory and CPU register variables; both must stay in sync.
	// TODO(deparker): should be possible to refactor the codebase a bit to clean this up
	// and share the constant instead of duplicating it.
	fakeAddressUnresolv = 0xbeed000000000000
	maxValSize          = 8192 // MAX_VAL_SIZE from function_vals.bpf.h
	maxDerefs           = 8    // MAX_DEREFS from function_vals.bpf.h

	// MaxDerefEntrySize is the number of bytes per individual deref entry slot
	// in the ring buffer. Must match DEREF_ENTRY_SIZE in function_vals.bpf.h.
	MaxDerefEntrySize = 2048

	maxDerefSize = maxDerefs * MaxDerefEntrySize // total deref region per param (16384)

	maxSliceElems          = 64
	defaultUnknownTypeSize = 8

	// Event type tags matching the BPF wire format.
	eventTypeHeader = 0
	eventTypeParam  = 1

	// Wire sizes of packed BPF ring buffer events.
	// Fields: type(1) + goroutine_id(8) + fn_addr(8) + is_ret(1) + n_params(4)
	eventHeaderWireSize = 1 + 8 + 8 + 1 + 4 // 22 bytes
	// Fields: type(1) + goroutine_id(8) + fn_addr(8) + param_idx(1) + is_ret(1) + kind(4) + val_size(4) + n_derefs(4) + deref_sizes(maxDerefs*4)
	paramEventWireSize = 1 + 8 + 8 + 1 + 1 + 4 + 4 + 4 + maxDerefs*4 // 63 bytes

	// paramEventDerefSizesOffset is the byte offset of Deref_sizes[0] in the
	// param event wire format: type(1)+goroutine_id(8)+fn_addr(8)+param_idx(1)+is_ret(1)+kind(4)+val_size(4)+n_derefs(4)=31.
	paramEventDerefSizesOffset = paramEventWireSize - maxDerefs*4

	maxPendingEvents = 1000
)

// deref_entry_t tracks deref_entry_t from function_vals.bpf.h
type deref_entry_t struct {
	offset uint32
	size   uint32
}

// function_parameter_t tracks function_parameter_t from function_vals.bpf.h
type function_parameter_t struct {
	kind     uint32
	size     uint32
	offset   int32
	in_reg   bool
	_        [3]byte // padding to align n_pieces to 4-byte boundary
	n_pieces int32
	reg_nums [6]int32

	n_derefs uint32
	derefs   [8]deref_entry_t

	val_size         uint32
	total_deref_size uint32
}

// function_parameter_list_t tracks function_parameter_list_t from function_vals.bpf.h
type function_parameter_list_t struct {
	goid_offset   uint32
	_             [4]byte
	g_addr_offset uint64

	fn_addr uint64
	is_ret  bool
	_       [3]byte

	n_parameters uint32
	params       [6]function_parameter_t

	n_ret_parameters uint32
	ret_params       [6]function_parameter_t
}

// event_header_t mirrors the packed C event_header_t.
type event_header_t struct {
	Type         uint8
	Goroutine_id int64
	Fn_addr      uint64
	Is_ret       bool
	N_params     uint32
}

// param_event_t is the packed wire format for PARAM events from the BPF ring buffer.
type param_event_t struct {
	Type         uint8
	Goroutine_id int64
	Fn_addr      uint64
	Param_idx    uint8
	Is_ret       bool
	Kind         uint32
	Val_size     uint32
	N_derefs     uint32
	Deref_sizes  [8]uint32
}

// dwarfTypeKey identifies a parameter for DWARF type lookup using a global
// index: input params are numbered 0..n-1, return params n..n+m-1.
type dwarfTypeKey struct {
	fnAddr   uint64
	paramIdx int
}

// paramMeta holds DWARF metadata for a traced parameter, populated during
// UpdateArgMap and looked up when parsing ring buffer PARAM events.
type paramMeta struct {
	dwarfType godwarf.Type
	name      string
}

// pendingKey associates PARAM events with their HEADER in the ring buffer
// protocol. Each uprobe hit produces one HEADER followed by N PARAM events;
// this key groups them so params can be collected until the set is complete.
type pendingKey struct {
	goroutineID int64
	fnAddr      uint64
	isRet       bool
}

type pendingEvent struct {
	header event_header_t
	params []*RawUProbeParam
}

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -tags "go1.16" -target amd64 trace bpf/trace.bpf.c -- -I./bpf/include

type EBPFContext struct {
	objs       *traceObjects
	bpfEvents  chan []byte
	bpfRingBuf *ringbuf.Reader
	executable *link.Executable
	bpfArgMap  *ebpf.Map
	links      []link.Link

	parsedBpfEvents []RawUProbeParams
	m               sync.Mutex

	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup

	// paramInfo maps a global param index to its DWARF type and name.
	// Input params occupy indices 0..n-1; return params n..n+m-1.
	// Populated during UpdateArgMap, read during ring buffer event parsing.
	paramInfo    map[dwarfTypeKey]paramMeta
	nInputParams map[uint64]int // fnAddr → number of input parameters

	pendingEvents map[pendingKey]*pendingEvent
}

func (ctx *EBPFContext) Close() {
	if ctx.cancel != nil {
		ctx.cancel()
	}

	// Wait for pollEvents to finish draining. pollEvents uses a 10ms periodic
	// deadline so Read() unblocks naturally; no SetDeadline needed here.
	ctx.wg.Wait()

	ctx.m.Lock()
	for k, pe := range ctx.pendingEvents {
		ctx.emitParsedEvent(pe)
		delete(ctx.pendingEvents, k)
	}
	ctx.m.Unlock()

	if ctx.bpfRingBuf != nil {
		ctx.bpfRingBuf.Close()
	}

	for _, l := range ctx.links {
		l.Close()
	}

	if ctx.objs != nil {
		ctx.objs.Close()
	}
}

func (ctx *EBPFContext) AttachUprobe(pid int, name string, offset uint64) error {
	if ctx.executable == nil {
		return errors.New("no eBPF program loaded")
	}
	l, err := ctx.executable.Uprobe(name, ctx.objs.tracePrograms.UprobeDlvTrace, &link.UprobeOptions{PID: pid, Address: offset})
	ctx.links = append(ctx.links, l)
	return err
}

func (ctx *EBPFContext) UpdateArgMap(key uint64, goidOffset int64, args []UProbeArgMap, gAddrOffset uint64, isret bool) error {
	if ctx.bpfArgMap == nil {
		return errors.New("eBPF map not loaded")
	}

	// Store DWARF types and parameter names for later lookup during ring buffer
	// event parsing. Uses a global index: input params at 0..n-1, return params
	// at n..n+m-1. Held under ctx.m to prevent data race with pollEvents.
	ctx.m.Lock()
	if !isret {
		ctx.nInputParams[key] = len(args)
	}
	nInputs := ctx.nInputParams[key]
	for i, arg := range args {
		idx := i
		if isret {
			idx = nInputs + i
		}
		k := dwarfTypeKey{fnAddr: key, paramIdx: idx}
		ctx.paramInfo[k] = paramMeta{dwarfType: arg.DwarfType, name: arg.Name}
	}
	ctx.m.Unlock()

	params := createFunctionParameterList(key, goidOffset, args, isret)
	params.g_addr_offset = gAddrOffset
	return ctx.bpfArgMap.Update(unsafe.Pointer(&key), unsafe.Pointer(&params), ebpf.UpdateAny)
}

func (ctx *EBPFContext) GetBufferedTracepoints() []RawUProbeParams {
	ctx.m.Lock()
	defer ctx.m.Unlock()

	if len(ctx.parsedBpfEvents) == 0 {
		return make([]RawUProbeParams, 0)
	}

	events := make([]RawUProbeParams, len(ctx.parsedBpfEvents))
	copy(events, ctx.parsedBpfEvents)
	ctx.parsedBpfEvents = ctx.parsedBpfEvents[:0]
	return events
}

func LoadEBPFTracingProgram(path string) (*EBPFContext, error) {
	var (
		ctx  EBPFContext
		err  error
		objs traceObjects
	)

	if err = rlimit.RemoveMemlock(); err != nil {
		return nil, fmt.Errorf("failed to remove memlock limit (try running with CAP_SYS_RESOURCE or as root): %w", err)
	}
	ctx.executable, err = link.OpenExecutable(path)
	if err != nil {
		return nil, err
	}

	if err := loadTraceObjects(&objs, nil); err != nil {
		return nil, err
	}
	ctx.objs = &objs

	ctx.bpfRingBuf, err = ringbuf.NewReader(objs.Events)
	if err != nil {
		return nil, err
	}

	ctx.bpfArgMap = objs.ArgMap
	ctx.paramInfo = make(map[dwarfTypeKey]paramMeta)
	ctx.nInputParams = make(map[uint64]int)
	ctx.pendingEvents = make(map[pendingKey]*pendingEvent)

	ctx.ctx, ctx.cancel = context.WithCancel(context.Background())

	ctx.wg.Add(1)
	go ctx.pollEvents()

	return &ctx, nil
}

// pollEvents reads events from the ring buffer and stores them for retrieval.
// This goroutine runs until the context is cancelled, then drains any events
// already buffered in the ring buffer before returning.
//
// A 10ms periodic deadline is set before each Read() call. This ensures
// Read() unblocks periodically to check for context cancellation, without
// requiring SetDeadline to be called from Close() while Read() holds r.mu
// (which would deadlock since SetDeadline also acquires r.mu).
func (ctx *EBPFContext) pollEvents() {
	defer ctx.wg.Done()

	for {
		if ctx.ctx.Err() != nil {
			ctx.drainRingBuf()
			return
		}

		// Set a short deadline before Read() so we unblock every 10ms to
		// check context cancellation. SetDeadline is safe here because Read()
		// is not yet running (both SetDeadline and Read() acquire r.mu).
		ctx.bpfRingBuf.SetDeadline(time.Now().Add(10 * time.Millisecond))
		e, err := ctx.bpfRingBuf.Read()
		if err != nil {
			if errors.Is(err, os.ErrDeadlineExceeded) {
				// Deadline fired — loop back and check context.
				continue
			}
			if ctx.ctx.Err() != nil {
				ctx.drainRingBuf()
			}
			return
		}

		ctx.storeEvent(e.RawSample)
	}
}

// drainRingBuf reads and stores all events currently buffered in the ring
// buffer. It sets a 50ms deadline so Read() returns quickly once the buffer
// is empty, rather than blocking indefinitely.
func (ctx *EBPFContext) drainRingBuf() {
	ctx.bpfRingBuf.SetDeadline(time.Now().Add(50 * time.Millisecond))
	for {
		e, err := ctx.bpfRingBuf.Read()
		if err != nil {
			return
		}
		ctx.storeEvent(e.RawSample)
	}
}

// storeEvent dispatches a raw ring buffer sample by event type.
func (ctx *EBPFContext) storeEvent(raw []byte) {
	if len(raw) < 1 {
		return
	}
	switch raw[0] {
	case eventTypeHeader:
		ctx.handleHeaderEvent(raw)
	case eventTypeParam:
		ctx.handleParamEvent(raw)
	}
}

func parseEventHeader(b []byte) (event_header_t, bool) {
	if len(b) < eventHeaderWireSize {
		return event_header_t{}, false
	}
	var h event_header_t
	h.Type = b[0]
	h.Goroutine_id = int64(binary.LittleEndian.Uint64(b[1:9]))
	h.Fn_addr = binary.LittleEndian.Uint64(b[9:17])
	h.Is_ret = b[17] != 0
	h.N_params = binary.LittleEndian.Uint32(b[18:22])
	return h, true
}

func parseParamEvent(b []byte) (param_event_t, bool) {
	if len(b) < paramEventWireSize {
		return param_event_t{}, false
	}
	var p param_event_t
	p.Type = b[0]
	p.Goroutine_id = int64(binary.LittleEndian.Uint64(b[1:9]))
	p.Fn_addr = binary.LittleEndian.Uint64(b[9:17])
	p.Param_idx = b[17]
	p.Is_ret = b[18] != 0
	p.Kind = binary.LittleEndian.Uint32(b[19:23])
	p.Val_size = binary.LittleEndian.Uint32(b[23:27])
	p.N_derefs = binary.LittleEndian.Uint32(b[27:31])
	for i := 0; i < 8; i++ {
		off := paramEventDerefSizesOffset + i*4
		p.Deref_sizes[i] = binary.LittleEndian.Uint32(b[off : off+4])
	}
	return p, true
}

func (ctx *EBPFContext) handleHeaderEvent(raw []byte) {
	hdr, ok := parseEventHeader(raw)
	if !ok {
		return
	}
	key := pendingKey{
		goroutineID: hdr.Goroutine_id,
		fnAddr:      hdr.Fn_addr,
		isRet:       hdr.Is_ret,
	}

	ctx.m.Lock()
	defer ctx.m.Unlock()
	if old, exists := ctx.pendingEvents[key]; exists {
		ctx.emitParsedEvent(old)
		delete(ctx.pendingEvents, key)
	}
	if len(ctx.pendingEvents) >= maxPendingEvents {
		for k, pe := range ctx.pendingEvents {
			ctx.emitParsedEvent(pe)
			delete(ctx.pendingEvents, k)
		}
	}
	if hdr.N_params == 0 {
		ctx.parsedBpfEvents = append(ctx.parsedBpfEvents, RawUProbeParams{
			FnAddr:      int(hdr.Fn_addr),
			GoroutineID: int(hdr.Goroutine_id),
			IsRet:       hdr.Is_ret,
		})
	} else {
		if hdr.N_params > 6 { // BPF-side MAX_PARAMS_PER_EVENT
			return
		}
		ctx.pendingEvents[key] = &pendingEvent{
			header: hdr,
			params: make([]*RawUProbeParam, hdr.N_params),
		}
	}
}

func (ctx *EBPFContext) handleParamEvent(raw []byte) {
	pe, ok := parseParamEvent(raw)
	if !ok {
		return
	}
	key := pendingKey{
		goroutineID: pe.Goroutine_id,
		fnAddr:      pe.Fn_addr,
		isRet:       pe.Is_ret,
	}

	ctx.m.Lock()
	defer ctx.m.Unlock()

	pending, exists := ctx.pendingEvents[key]
	if !exists {
		logflags.DebuggerLogger().Debugf("ebpf: dropped PARAM event for fn=%#x goroutine=%d is_ret=%v param_idx=%d: no matching HEADER (ring buffer loss?)", pe.Fn_addr, pe.Goroutine_id, pe.Is_ret, pe.Param_idx)
		return
	}

	if int(pe.Param_idx) >= len(pending.params) {
		logflags.DebuggerLogger().Debugf("ebpf: dropped PARAM event for fn=%#x goroutine=%d param_idx=%d: out of range (expected 0..%d)", pe.Fn_addr, pe.Goroutine_id, pe.Param_idx, len(pending.params)-1)
		return
	}

	iparam := &RawUProbeParam{}
	iparam.Kind = reflect.Kind(pe.Kind)
	iparam.Addr = fakeAddressUnresolv

	// Extract val data from the wire format after the param event header.
	valSize := min(int(pe.Val_size), maxValSize)
	nDerefs := min(int(pe.N_derefs), maxDerefs)

	dataStart := paramEventWireSize
	if valSize > 0 && dataStart+valSize <= len(raw) {
		iparam.Data = make([]byte, valSize)
		copy(iparam.Data, raw[dataStart:dataStart+valSize])
	} else {
		iparam.Data = make([]byte, 0)
	}

	// derefRegionStart is correct only when n_derefs > 0: the BPF program
	// always emits a full MAX_VAL_SIZE-byte val region before the deref
	// slots when any derefs are present, so the fixed stride formula holds.
	// For n_derefs == 0 the event is shorter, but derefRegionStart is only
	// used below when totalDerefSize > 0, which implies n_derefs > 0.
	derefRegionStart := dataStart + maxValSize
	var totalDerefSize int
	for j := 0; j < nDerefs; j++ {
		sz := min(int(pe.Deref_sizes[j]), MaxDerefEntrySize)
		totalDerefSize += sz
	}

	if totalDerefSize > 0 {
		iparam.DerefData = make([]byte, totalDerefSize)
		dst := 0
		truncated := false
		for j := 0; j < nDerefs; j++ {
			sz := min(int(pe.Deref_sizes[j]), MaxDerefEntrySize)
			if sz == 0 {
				continue
			}
			srcOff := derefRegionStart + j*MaxDerefEntrySize
			if srcOff+sz <= len(raw) {
				copy(iparam.DerefData[dst:dst+sz], raw[srcOff:srcOff+sz])
			} else {
				logflags.DebuggerLogger().Debugf("ebpf: deref entry %d for fn=%#x param_idx=%d truncated: event len=%d, needed bytes [%d:%d]", j, pe.Fn_addr, pe.Param_idx, len(raw), srcOff, srcOff+sz)
				truncated = true
			}
			dst += sz
		}
		if truncated {
			iparam.Unreadable = fmt.Errorf("eBPF ring buffer event truncated")
		}
	}

	if totalDerefSize > 0 {
		iparam.Pieces = []op.Piece{
			{Size: valSize, Kind: op.AddrPiece, Val: fakeAddressUnresolv},
			{Size: totalDerefSize, Kind: op.AddrPiece, Val: fakeAddressUnresolv + uint64(valSize)},
		}
	} else {
		iparam.Pieces = []op.Piece{
			{Size: valSize, Kind: op.AddrPiece, Val: fakeAddressUnresolv},
		}
	}

	// Map BPF's per-direction param_idx to the global DWARF type index.
	// Input params: 0..n-1, return params: n..n+m-1.
	globalIdx := int(pe.Param_idx)
	if pe.Is_ret {
		globalIdx = ctx.nInputParams[pe.Fn_addr] + int(pe.Param_idx)
	}
	dtKey := dwarfTypeKey{fnAddr: pe.Fn_addr, paramIdx: globalIdx}
	if meta, ok := ctx.paramInfo[dtKey]; ok {
		iparam.DwarfType = meta.dwarfType
		iparam.Name = meta.name
	}

	if iparam.DwarfType != nil {
		resolvedType := godwarf.ResolveTypedef(iparam.DwarfType)
		iparam.RealType = resolvedType
		switch resolvedType.(type) {
		case *godwarf.StructType:
			iparam.Kind = reflect.Struct
		case *godwarf.ArrayType:
			iparam.Kind = reflect.Array
		case *godwarf.SliceType:
			iparam.Kind = reflect.Slice
		default:
			if k := resolvedType.Common().ReflectKind; k != reflect.Invalid {
				iparam.Kind = k
			}
		}
		if iparam.Kind == reflect.String && len(iparam.Data) >= 16 {
			iparam.Base = fakeAddressUnresolv + uint64(valSize)
			iparam.Len = int64(binary.LittleEndian.Uint64(iparam.Data[8:16]))
		}
	} else {
		synthesizeTypeFromKind(iparam, pe.Val_size)
	}

	pending.params[pe.Param_idx] = iparam

	complete := true
	for _, p := range pending.params {
		if p == nil {
			complete = false
			break
		}
	}

	if complete {
		ctx.emitParsedEvent(pending)
		delete(ctx.pendingEvents, key)
	}
}

func (ctx *EBPFContext) emitParsedEvent(pe *pendingEvent) {
	result := RawUProbeParams{
		FnAddr:      int(pe.header.Fn_addr),
		GoroutineID: int(pe.header.Goroutine_id),
		IsRet:       pe.header.Is_ret,
	}
	for _, p := range pe.params {
		if p == nil {
			continue
		}
		if pe.header.Is_ret {
			result.ReturnParams = append(result.ReturnParams, p)
		} else {
			result.InputParams = append(result.InputParams, p)
		}
	}
	ctx.parsedBpfEvents = append(ctx.parsedBpfEvents, result)
}

const maxStringDerefSize = 256

// BuildDerefPlan walks a DWARF type one level deep and produces a
// dereference plan for pointer fields that the eBPF program should chase.
// Returns the plan and the number of valid entries.
func BuildDerefPlan(typ godwarf.Type) (derefs [8]DerefEntry, numDerefs uint32) {
	// Named Go types (structs, pointers, etc.) are often DW_TAG_typedef
	// wrappers in DWARF. Resolve to the concrete type so the switch below
	// correctly matches StructType, PtrType, etc.
	typ = godwarf.ResolveTypedef(typ)
	switch t := typ.(type) {
	case *godwarf.PtrType:
		pointedSize := t.Type.Size()
		if pointedSize <= 0 {
			pointedSize = defaultUnknownTypeSize
		}
		derefs[0] = DerefEntry{Offset: 0, Size: uint32(min(pointedSize, MaxDerefEntrySize))}
		numDerefs = 1

	case *godwarf.StructType:
		numDerefs = buildStructDerefPlan(t, &derefs)

	case *godwarf.ArrayType:
		numDerefs = buildArrayDerefPlan(t, &derefs)

	case *godwarf.SliceType:
		elemSize := t.ElemType.Size()
		if elemSize <= 0 {
			elemSize = defaultUnknownTypeSize
		}
		derefs[0] = DerefEntry{Offset: 0, Size: uint32(min(elemSize*maxSliceElems, MaxDerefEntrySize))}
		numDerefs = 1

	case *godwarf.StringType:
		// String header: {ptr, len}. Deref the data pointer at offset 0.
		derefs[0] = DerefEntry{Offset: 0, Size: maxStringDerefSize}
		numDerefs = 1
	}

	return
}

// buildStructDerefPlan builds dereference entries for pointer-like fields
// in a struct. Returns the number of deref entries.
func buildStructDerefPlan(st *godwarf.StructType, derefs *[8]DerefEntry) uint32 {
	var count uint32

	// First pass: count pointer-like fields (resolve typedefs so named types
	// wrapping pointer/string/slice are not missed).
	var ptrFieldCount int
	for _, field := range st.Field {
		if isDerefableType(godwarf.ResolveTypedef(field.Type)) {
			ptrFieldCount++
		}
	}
	if ptrFieldCount == 0 {
		return 0
	}

	// Compute per-deref budget, capped at the BPF slot size.
	budget := int64(maxDerefSize)
	if ptrFieldCount > maxDerefs {
		ptrFieldCount = maxDerefs
	}
	perDerefBudget := min(budget/int64(ptrFieldCount), MaxDerefEntrySize)

	for _, field := range st.Field {
		if count >= maxDerefs {
			break
		}
		switch ft := godwarf.ResolveTypedef(field.Type).(type) {
		case *godwarf.PtrType:
			pointedSize := ft.Type.Size()
			if pointedSize <= 0 {
				pointedSize = defaultUnknownTypeSize
			}
			derefs[count] = DerefEntry{
				Offset: uint32(field.ByteOffset),
				Size:   uint32(min(pointedSize, perDerefBudget)),
			}
			count++

		case *godwarf.StringType:
			derefs[count] = DerefEntry{
				Offset: uint32(field.ByteOffset),
				Size:   uint32(min(int64(maxStringDerefSize), perDerefBudget)),
			}
			count++

		case *godwarf.SliceType:
			elemSize := ft.ElemType.Size()
			if elemSize <= 0 {
				elemSize = defaultUnknownTypeSize
			}
			derefs[count] = DerefEntry{
				Offset: uint32(field.ByteOffset),
				Size:   uint32(min(elemSize*maxSliceElems, perDerefBudget)),
			}
			count++
		}
	}

	return count
}

// buildArrayDerefPlan builds dereference entries for arrays whose elements
// contain pointers. Returns the number of deref entries.
func buildArrayDerefPlan(at *godwarf.ArrayType, derefs *[8]DerefEntry) uint32 {
	// Only build deref entries if the element type has pointer-like fields.
	// For arrays of scalars, no dereference is needed.
	elemType := godwarf.ResolveTypedef(at.Type)
	if !typeContainsPointers(elemType) {
		return 0
	}

	// For arrays of structs with pointers, we build deref entries
	// for the pointer fields of each element, up to the deref budget.
	var count uint32
	elemSize := elemType.Size()
	if elemSize <= 0 {
		return 0
	}

	numElems := at.Count
	if numElems <= 0 {
		return 0
	}

	for i := int64(0); i < numElems && count < maxDerefs; i++ {
		elemOffset := i * elemSize

		// For each element, check if it's a struct with pointer fields.
		switch et := elemType.(type) {
		case *godwarf.PtrType:
			pointedSize := et.Type.Size()
			if pointedSize <= 0 {
				pointedSize = defaultUnknownTypeSize
			}
			pointedSize = min(pointedSize, MaxDerefEntrySize)
			derefs[count] = DerefEntry{
				Offset: uint32(elemOffset),
				Size:   uint32(pointedSize),
			}
			count++
		case *godwarf.StructType:
			for _, field := range et.Field {
				if count >= maxDerefs {
					break
				}
				fieldOffset := elemOffset + field.ByteOffset
				switch ft := godwarf.ResolveTypedef(field.Type).(type) {
				case *godwarf.PtrType:
					pointedSize := ft.Type.Size()
					if pointedSize <= 0 {
						pointedSize = defaultUnknownTypeSize
					}
					pointedSize = min(pointedSize, MaxDerefEntrySize)
					derefs[count] = DerefEntry{
						Offset: uint32(fieldOffset),
						Size:   uint32(pointedSize),
					}
					count++
				case *godwarf.StringType:
					derefs[count] = DerefEntry{
						Offset: uint32(fieldOffset),
						Size:   uint32(min(int64(maxStringDerefSize), MaxDerefEntrySize)),
					}
					count++
				case *godwarf.SliceType:
					elemSz := ft.ElemType.Size()
					if elemSz <= 0 {
						elemSz = defaultUnknownTypeSize
					}
					derefSize := min(elemSz*maxSliceElems, MaxDerefEntrySize)
					derefs[count] = DerefEntry{
						Offset: uint32(fieldOffset),
						Size:   uint32(derefSize),
					}
					count++
				}
			}
		}
	}

	return count
}

// isDerefableType returns true if a type is a pointer, string, or slice
// (types that require dereferencing).
func isDerefableType(t godwarf.Type) bool {
	switch t.(type) {
	case *godwarf.PtrType, *godwarf.StringType, *godwarf.SliceType:
		return true
	}
	return false
}

// typeContainsPointers returns true if a type contains pointer-like fields
// that benefit from dereferencing.
func typeContainsPointers(t godwarf.Type) bool {
	t = godwarf.ResolveTypedef(t)
	switch ct := t.(type) {
	case *godwarf.PtrType, *godwarf.StringType, *godwarf.SliceType:
		return true
	case *godwarf.StructType:
		for _, field := range ct.Field {
			if isDerefableType(godwarf.ResolveTypedef(field.Type)) {
				return true
			}
		}
	}
	return false
}

// synthesizeTypeFromKind creates a godwarf.Type from a reflect.Kind
// for parameters that don't have a full DWARF type (backward
// compatibility with scalar types).
func synthesizeTypeFromKind(iparam *RawUProbeParam, valSize uint32) {
	vs := int64(valSize)
	switch iparam.Kind {
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.Uintptr:
		iparam.RealType = &godwarf.UintType{BasicType: godwarf.BasicType{CommonType: godwarf.CommonType{ByteSize: vs}}}
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		iparam.RealType = &godwarf.IntType{BasicType: godwarf.BasicType{CommonType: godwarf.CommonType{ByteSize: vs}}}
	case reflect.Bool:
		iparam.RealType = &godwarf.BoolType{BasicType: godwarf.BasicType{CommonType: godwarf.CommonType{ByteSize: 1, ReflectKind: reflect.Bool}}}
	case reflect.Float32, reflect.Float64:
		iparam.RealType = &godwarf.FloatType{BasicType: godwarf.BasicType{CommonType: godwarf.CommonType{ByteSize: vs, ReflectKind: iparam.Kind}}}
	case reflect.Complex64, reflect.Complex128:
		iparam.RealType = &godwarf.ComplexType{BasicType: godwarf.BasicType{CommonType: godwarf.CommonType{ByteSize: vs, ReflectKind: iparam.Kind}}}
	case reflect.Pointer, reflect.UnsafePointer:
		iparam.Kind = reflect.Uintptr
		iparam.RealType = &godwarf.UintType{BasicType: godwarf.BasicType{CommonType: godwarf.CommonType{ByteSize: vs, ReflectKind: reflect.Uintptr}}}
	case reflect.Slice:
		iparam.Kind = reflect.Uintptr
		iparam.RealType = &godwarf.UintType{BasicType: godwarf.BasicType{CommonType: godwarf.CommonType{ByteSize: 8, ReflectKind: reflect.Uintptr}}}
	case reflect.String:
		if len(iparam.Data) >= 16 {
			iparam.Base = fakeAddressUnresolv + uint64(valSize)
			iparam.Len = int64(binary.LittleEndian.Uint64(iparam.Data[8:16]))
		}
		iparam.RealType = &godwarf.StringType{
			StructType: godwarf.StructType{
				CommonType: godwarf.CommonType{ByteSize: 16, ReflectKind: reflect.String},
				Kind:       "struct",
			},
		}
	case reflect.Map:
		iparam.Unreadable = fmt.Errorf("map type not yet supported by ebpf tracing")
	case reflect.Chan:
		iparam.Unreadable = fmt.Errorf("chan type not yet supported by ebpf tracing")
	case reflect.Interface:
		iparam.Unreadable = fmt.Errorf("interface type not yet supported by ebpf tracing")
	case reflect.Func:
		iparam.Unreadable = fmt.Errorf("func type not yet supported by ebpf tracing")
	case reflect.Struct:
		iparam.Unreadable = fmt.Errorf("struct type not yet supported by ebpf tracing without DWARF type")
	case reflect.Array:
		iparam.Unreadable = fmt.Errorf("array type not yet supported by ebpf tracing without DWARF type")
	default:
		iparam.Unreadable = fmt.Errorf("unrecognized reflect.Kind %d from eBPF", iparam.Kind)
	}
}

func createFunctionParameterList(entry uint64, goidOffset int64, args []UProbeArgMap, isret bool) function_parameter_list_t {
	var params function_parameter_list_t
	params.goid_offset = uint32(goidOffset)
	params.fn_addr = entry
	params.is_ret = isret
	params.n_parameters = 0
	params.n_ret_parameters = 0
	for _, arg := range args {
		var param function_parameter_t
		param.size = uint32(arg.Size)
		param.offset = int32(arg.Offset)
		param.kind = uint32(arg.Kind)

		// Cap val_size at MAX_VAL_SIZE.
		if arg.Size > maxValSize {
			param.val_size = maxValSize
		} else {
			param.val_size = uint32(arg.Size)
		}

		// Copy dereference plan. Cap each individual deref size at
		// MaxDerefEntrySize (DEREF_ENTRY_SIZE in BPF) so the BPF program's
		// fixed-stride ring buffer slots are not exceeded.
		n := min(arg.NumDerefs, maxDerefs)
		param.n_derefs = n
		var totalDerefSize uint32
		for i := uint32(0); i < n; i++ {
			sz := min(arg.Derefs[i].Size, MaxDerefEntrySize)
			param.derefs[i].offset = arg.Derefs[i].Offset
			param.derefs[i].size = sz
			totalDerefSize += sz
		}
		totalDerefSize = min(totalDerefSize, maxDerefSize)
		param.total_deref_size = totalDerefSize

		if arg.InReg {
			param.in_reg = true
			param.n_pieces = int32(len(arg.Pieces))
			for i := range arg.Pieces {
				if i > 5 {
					break
				}
				param.reg_nums[i] = int32(arg.Pieces[i])
			}
		}
		if !arg.Ret {
			params.params[params.n_parameters] = param
			params.n_parameters++
		} else {
			params.ret_params[params.n_ret_parameters] = param
			params.n_ret_parameters++
		}
	}
	return params
}

func AddressToOffset(f *elf.File, addr uint64) (uint64, error) {
	sectionsToSearchForSymbol := []*elf.Section{}

	for i := range f.Sections {
		if f.Sections[i].Flags == elf.SHF_ALLOC+elf.SHF_EXECINSTR {
			sectionsToSearchForSymbol = append(sectionsToSearchForSymbol, f.Sections[i])
		}
	}

	var executableSection *elf.Section

	// Find what section the symbol is in by checking the executable section's
	// addr space.
	for m := range sectionsToSearchForSymbol {
		if addr >= sectionsToSearchForSymbol[m].Addr &&
			addr < sectionsToSearchForSymbol[m].Addr+sectionsToSearchForSymbol[m].Size {
			executableSection = sectionsToSearchForSymbol[m]
		}
	}

	if executableSection == nil {
		return 0, errors.New("could not find symbol in executable sections of binary")
	}

	return uint64(addr - executableSection.Addr + executableSection.Offset), nil
}
