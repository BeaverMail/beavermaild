package pluginhost_test

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/BeaverMail/beavermaild/internal/pluginhost"
)

func TestProbePluginDescriptor(t *testing.T) {
	exe := buildPlugin(t, "internal/pluginhost/testdata/metadataplugin")
	desc, ok, err := pluginhost.ProbePluginDescriptorForTest(exe)
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Fatal("expected descriptor")
	}
	if len(desc.Command) != 2 || desc.CliFlags[0].Flag != "srcdir" {
		t.Fatalf("%+v", desc)
	}
}

func TestLoadRegistryPluginProbe(t *testing.T) {
	dir := t.TempDir()
	exe := filepath.Join(dir, "beaver-plugin-widget-frob")
	if err := copyFile(exe, buildPlugin(t, "internal/pluginhost/testdata/metadataplugin")); err != nil {
		t.Fatal(err)
	}

	reg, err := pluginhost.LoadRegistry(dir)
	if err != nil {
		t.Fatal(err)
	}
	entries := reg.List()
	if len(entries) != 1 {
		t.Fatalf("entries: %+v", entries)
	}
	e := entries[0]
	if e.Op() != "widget/frob" {
		t.Fatalf("op=%q", e.Op())
	}
	if len(e.CliFlags) != 1 || e.CliFlags[0].Flag != "srcdir" {
		t.Fatalf("cli_flags: %+v", e.CliFlags)
	}
}

func buildPlugin(t *testing.T, pkg string) string {
	t.Helper()
	root := findModuleRoot(t)
	out := filepath.Join(t.TempDir(), "beaver-plugin-test")
	cmd := exec.Command("go", "build", "-o", out, filepath.Join(root, pkg))
	if b, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("build %s: %v\n%s", pkg, err, b)
	}
	return out
}

func copyFile(dst, src string) error {
	b, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	return os.WriteFile(dst, b, 0o755)
}

func findModuleRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("go.mod not found")
		}
		dir = parent
	}
}
