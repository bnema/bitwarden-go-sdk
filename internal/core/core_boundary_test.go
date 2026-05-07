package core_test

import (
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestNoAdapterImports ensures no package under internal/core imports anything
// from internal/adapters, preserving the core/adapters boundary.
func TestNoAdapterImports(t *testing.T) {
	root := "."

	err := filepath.Walk(root, func(path string, fi os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		// Skip vendor and hidden directories.
		if fi.IsDir() && (fi.Name() == "vendor" || strings.HasPrefix(fi.Name(), ".")) {
			return filepath.SkipDir
		}

		// Only process .go files.
		if fi.IsDir() || !strings.HasSuffix(fi.Name(), ".go") {
			return nil
		}

		// Parse the file.
		fset := token.NewFileSet()
		f, err := parser.ParseFile(fset, path, nil, parser.ImportsOnly)
		if err != nil {
			// Skip files that can't be parsed (e.g. build-constrained).
			return nil
		}

		for _, imp := range f.Imports {
			importPath := strings.Trim(imp.Path.Value, `"`)

			// Check for direct adapter import.
			if strings.Contains(importPath, "/internal/adapters") {
				t.Errorf(
					"%s imports %s which crosses the core → adapters boundary",
					path, importPath,
				)
			}
		}

		return nil
	})
	if err != nil {
		t.Fatalf("walk failed: %v", err)
	}
}
