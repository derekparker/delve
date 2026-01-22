//go:build linux && amd64 && cgo && go1.16

package ebpf

import (
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"
)

// TestVerifyEBPFProgram loads the eBPF program to verify it passes the kernel verifier.
// This provides fast feedback without needing to set up a full trace scenario.
func TestVerifyEBPFProgram(t *testing.T) {
	// Remove memlock limit
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Skipf("Failed to remove memlock limit (requires CAP_SYS_RESOURCE): %v", err)
	}

	// Load the eBPF objects with larger log buffer to see full verifier output on failure
	opts := &ebpf.CollectionOptions{
		Programs: ebpf.ProgramOptions{
			LogLevel: ebpf.LogLevelInstruction,
			LogSize:  16 * 1024 * 1024, // 16MB log buffer
		},
	}

	var objs traceObjects
	if err := loadTraceObjects(&objs, opts); err != nil {
		t.Fatalf("Failed to load eBPF objects (verifier rejection): %v", err)
	}
	defer objs.Close()

	// Check that the program was loaded successfully
	if objs.tracePrograms.UprobeDlvTrace == nil {
		t.Fatal("uprobe__dlv_trace program is nil")
	}

	// Verify the program info
	info, err := objs.tracePrograms.UprobeDlvTrace.Info()
	if err != nil {
		t.Fatalf("Failed to get program info: %v", err)
	}

	t.Logf("eBPF program loaded successfully:")
	t.Logf("  Name: %s", info.Name)
	t.Logf("  Type: %s", info.Type)
	if id, ok := info.ID(); ok {
		t.Logf("  ID: %d", id)
	}

	// Verify maps exist
	if objs.traceMaps.ArgMap == nil {
		t.Fatal("arg_map is nil")
	}
	if objs.traceMaps.Events == nil {
		t.Fatal("events ring buffer is nil")
	}

	// Check map info
	argMapInfo, err := objs.traceMaps.ArgMap.Info()
	if err != nil {
		t.Fatalf("Failed to get arg_map info: %v", err)
	}
	t.Logf("arg_map: MaxEntries=%d, KeySize=%d, ValueSize=%d",
		argMapInfo.MaxEntries, argMapInfo.KeySize, argMapInfo.ValueSize)

	eventsInfo, err := objs.traceMaps.Events.Info()
	if err != nil {
		t.Fatalf("Failed to get events info: %v", err)
	}
	t.Logf("events ring buffer: MaxEntries=%d", eventsInfo.MaxEntries)
}

// TestVerifyEBPFProgramVerbose is like TestVerifyEBPFProgram but with verbose verifier output.
// Run with: go test -v -run TestVerifyEBPFProgramVerbose
func TestVerifyEBPFProgramVerbose(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping verbose verifier test in short mode")
	}

	// Remove memlock limit
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Skipf("Failed to remove memlock limit (requires CAP_SYS_RESOURCE): %v", err)
	}

	// Create a spec with verbose verifier output
	spec, err := loadTrace()
	if err != nil {
		t.Fatalf("Failed to load trace spec: %v", err)
	}

	// Enable verifier log
	opts := &ebpf.CollectionOptions{
		Programs: ebpf.ProgramOptions{
			LogLevel: ebpf.LogLevelInstruction | ebpf.LogLevelStats,
			LogSize:  64 * 1024 * 1024, // 64MB log buffer
		},
	}

	// Load with verbose logging
	coll, err := ebpf.NewCollectionWithOptions(spec, *opts)
	if err != nil {
		t.Fatalf("Failed to load eBPF collection: %v", err)
	}
	defer coll.Close()

	t.Log("eBPF program loaded successfully with verbose verifier logging")
}
