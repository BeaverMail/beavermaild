package xfer_test

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/BeaverMail/beaver/internal/storage"
	"github.com/BeaverMail/beaver/internal/storage/mysql"
	"github.com/BeaverMail/beaver/internal/storage/sqlite"
	"github.com/BeaverMail/beaver/internal/storage/xfer"
)

func openSQLite(t *testing.T) storage.Store {
	t.Helper()
	store, err := sqlite.Open(context.Background(), "file:"+t.TempDir()+"/store.sqlite")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	return store
}

func putKey(t *testing.T, store storage.Store, account, doc uint32, val []byte) []byte {
	t.Helper()
	ctx := context.Background()
	key := storage.AppendKey(nil, storage.SubspaceMail, account, doc, 1, nil)
	batch := storage.NewBatch()
	if err := batch.SetRaw(key, val); err != nil {
		t.Fatal(err)
	}
	if err := store.Commit(ctx, batch); err != nil {
		t.Fatal(err)
	}
	return key
}

func TestExportImportRoundTrip(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	src := openSQLite(t)
	key := putKey(t, src, 7, 100, []byte("envelope"))

	var buf bytes.Buffer
	n, err := xfer.Export(ctx, src, &buf)
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatalf("exported %d want 1", n)
	}

	dst := openSQLite(t)
	got, err := xfer.Import(ctx, dst, bytes.NewReader(buf.Bytes()), xfer.ImportOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if got != 1 {
		t.Fatalf("imported %d want 1", got)
	}
	val, err := dst.Get(ctx, key)
	if err != nil {
		t.Fatal(err)
	}
	if string(val) != "envelope" {
		t.Fatalf("got %q", val)
	}
}

func TestImportRejectsNonEmpty(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	src := openSQLite(t)
	putKey(t, src, 1, 1, []byte("a"))
	var buf bytes.Buffer
	if _, err := xfer.Export(ctx, src, &buf); err != nil {
		t.Fatal(err)
	}

	dst := openSQLite(t)
	putKey(t, dst, 2, 2, []byte("existing"))
	_, err := xfer.Import(ctx, dst, bytes.NewReader(buf.Bytes()), xfer.ImportOptions{})
	if !errors.Is(err, xfer.ErrNotEmpty) {
		t.Fatalf("got %v want not empty", err)
	}

	_, err = xfer.Import(ctx, dst, bytes.NewReader(buf.Bytes()), xfer.ImportOptions{Force: true})
	if err != nil {
		t.Fatal(err)
	}
}

func TestImportRejectsFutureSchema(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	var buf bytes.Buffer
	buf.WriteString(xfer.Magic)
	var hdr [4]byte
	binary.BigEndian.PutUint32(hdr[:], uint32(storage.SchemaVersion)+1)
	buf.Write(hdr[:])

	dst := openSQLite(t)
	_, err := xfer.Import(ctx, dst, bytes.NewReader(buf.Bytes()), xfer.ImportOptions{})
	if !errors.Is(err, xfer.ErrSchemaTooNew) {
		t.Fatalf("got %v want schema too new", err)
	}
}

func TestImportBadMagic(t *testing.T) {
	t.Parallel()
	dst := openSQLite(t)
	_, err := xfer.Import(context.Background(), dst, strings.NewReader("NOPEKV1!!\n"), xfer.ImportOptions{})
	if !errors.Is(err, xfer.ErrBadMagic) {
		t.Fatalf("got %v", err)
	}
}

func TestIsEmptyAfterMigrate(t *testing.T) {
	t.Parallel()
	store := openSQLite(t)
	empty, err := xfer.IsEmpty(context.Background(), store)
	if err != nil {
		t.Fatal(err)
	}
	if !empty {
		t.Fatal("expected empty after migrate-only open")
	}
}

func TestExportImportMySQL(t *testing.T) {
	dsn := strings.TrimSpace(os.Getenv("BEAVER_TEST_MYSQL_DSN"))
	if dsn == "" {
		t.Skip("set BEAVER_TEST_MYSQL_DSN to run MySQL xfer test")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	src := openSQLite(t)
	key := putKey(t, src, 3, 9, []byte("mysql-xfer"))
	var buf bytes.Buffer
	if _, err := xfer.Export(ctx, src, &buf); err != nil {
		t.Fatal(err)
	}

	dst, err := mysql.Open(ctx, dsn)
	if err != nil {
		t.Skipf("mysql not reachable: %v", err)
	}
	t.Cleanup(func() { _ = dst.Close() })

	// Force so repeated test runs on shared DB succeed.
	if _, err := xfer.Import(ctx, dst, bytes.NewReader(buf.Bytes()), xfer.ImportOptions{Force: true}); err != nil {
		t.Fatal(err)
	}
	val, err := dst.Get(ctx, key)
	if err != nil {
		t.Fatal(err)
	}
	if string(val) != "mysql-xfer" {
		t.Fatalf("got %q", val)
	}
}
