package web

import (
	"io/fs"
	"strings"
	"testing"
)

func TestDistFSContainsIndexHTML(t *testing.T) {
	dfs := DistFS()
	data, err := fs.ReadFile(dfs, "index.html")
	if err != nil {
		t.Fatalf("read embedded index.html: %v", err)
	}
	if !strings.Contains(strings.ToLower(string(data)), "<html") {
		t.Fatalf("expected index.html to contain <html, got %q", string(data))
	}
}
