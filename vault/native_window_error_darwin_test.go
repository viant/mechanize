//go:build darwin && cgo

package vault

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"testing"
)

// Compile the real native classifier into a fixture without invoking the
// probe. No desktop process/window enumeration or AX permission check occurs.
func TestNativeProbePlatformStatusClassificationWithoutDesktopAccess(t *testing.T) {
	compiler, err := exec.LookPath("clang")
	if err != nil {
		t.Fatal(err)
	}
	cwd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	directory := t.TempDir()
	source := filepath.Join(directory, "probe-classifier.m")
	binary := filepath.Join(directory, "probe-classifier")
	program := "#include " + strconv.Quote(filepath.Join(cwd, "native_windows_darwin.m")) + fmt.Sprintf(`
int main(void) {
    if (vault_probe_ax_trust_denied != %d || vault_probe_process_invalid != %d || vault_probe_signature_invalid != %d ||
        vault_probe_ipc_unavailable != %d || vault_probe_window_shape_unavailable != %d || vault_probe_response_timeout != %d ||
        vault_probe_configuration_invalid != %d || vault_probe_console_inventory_unavailable != %d) return 1;
    if (vault_ax_failure(kAXErrorSuccess, 100000000) != 0) return 2;
    if (vault_ax_failure(kAXErrorCannotComplete, 0) != vault_probe_ipc_unavailable) return 3;
    if (vault_ax_failure(kAXErrorCannotComplete, 49999999) != vault_probe_ipc_unavailable) return 4;
    if (vault_ax_failure(kAXErrorCannotComplete, 50000000) != vault_probe_response_timeout) return 5;
    if (vault_ax_failure(kAXErrorFailure, 100000000) != vault_probe_ipc_unavailable) return 6;
    if (vault_ax_failure(kAXErrorAttributeUnsupported, 0) != vault_probe_window_shape_unavailable) return 7;
    if (vault_ax_failure(kAXErrorNoValue, 0) != vault_probe_window_shape_unavailable) return 8;
    if (vault_ax_failure(kAXErrorAPIDisabled, 0) != vault_probe_ipc_unavailable) return 9;
    return 0;
}
`, nativeProbeAXTrustDenied, nativeProbeProcessInvalid, nativeProbeSignatureInvalid, nativeProbeIPCUnavailable, nativeProbeWindowShapeUnavailable, nativeProbeResponseTimeout, nativeProbeConfigurationInvalid, nativeProbeConsoleInventoryUnavailable)
	if err = os.WriteFile(source, []byte(program), 0600); err != nil {
		t.Fatal(err)
	}
	if output, err := exec.Command(compiler, "-framework", "AppKit", "-framework", "ApplicationServices", "-framework", "Security", "-framework", "Foundation", source, "-o", binary).CombinedOutput(); err != nil {
		t.Fatalf("native classifier fixture failed to compile: %v: %s", err, output)
	}
	if err = exec.Command(binary).Run(); err != nil {
		t.Fatalf("native classifier contract mismatch: %v", err)
	}
}
