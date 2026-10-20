package pluginhost_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/BeaverMail/beaver/internal/pluginhost"
)

func TestLoadRegistryScanOnlyDefaultCommand(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "beaver-plugin-widget-frob"), []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
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
	if got := entries[0].Op(); got != "widget-frob" {
		t.Fatalf("command op = %q, want widget-frob", got)
	}
}

func TestLoadRegistryFindExactCommandOnly(t *testing.T) {
	dir := t.TempDir()
	exe := filepath.Join(dir, "beaver-plugin-widget-frob")
	if err := copyFile(exe, buildPlugin(t, "internal/pluginhost/testdata/metadataplugin")); err != nil {
		t.Fatal(err)
	}

	reg, err := pluginhost.LoadRegistry(dir)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := reg.Find([]string{"widget", "frob"}); !ok {
		t.Fatal("widget frob not found")
	}
	if _, ok := reg.Find([]string{"widget-frob"}); ok {
		t.Fatal("widget-frob must not match when list shows widget frob")
	}
}

func TestLoadRegistrySkipsBrokenPlugin(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "beaver-plugin-broken"), []byte("#!/bin/sh\necho 'not json'\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "beaver-plugin-widget-frob"), []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
		t.Fatal(err)
	}

	reg, err := pluginhost.LoadRegistry(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(reg.List()) != 1 || reg.List()[0].Exe != "beaver-plugin-widget-frob" {
		t.Fatalf("entries: %+v", reg.List())
	}
	if len(reg.Skipped()) != 1 {
		t.Fatalf("skipped: %v", reg.Skipped())
	}
}
