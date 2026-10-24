// Copyright 2026 Certen Protocol

package main

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// RB12-LEGACY-191 pin: the process must give the finality runtime its leg lister (Deps.Legacy) and the leg source its header store
// (WithLegacyHeaders). Without them the wiring line says "legacy_headers=off (no leg lister)" and the 191 legacy legs silently stay
// finality_included_unavailable{no_block_header}. The check reads the Go files of this package (wherever startFinality lives: main.go
// today, finality_start.go once Train 3 is merged), so it survives a move of the code and fails when a merge drops the hunk.
func TestTheProcessWiresTheLegacyHeaderLoopAndItsHeaderStore(t *testing.T) {
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	fset := token.NewFileSet()
	var legacyKey, withStore bool
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		src, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		file, err := parser.ParseFile(fset, f, src, 0)
		if err != nil {
			t.Fatal(err)
		}
		ast.Inspect(file, func(n ast.Node) bool {
			switch x := n.(type) {
			case *ast.CompositeLit:
				if sel, ok := x.Type.(*ast.SelectorExpr); ok && sel.Sel.Name == "Deps" {
					for _, e := range x.Elts {
						if kv, ok := e.(*ast.KeyValueExpr); ok {
							if k, ok := kv.Key.(*ast.Ident); ok && k.Name == "Legacy" {
								if v, isIdent := kv.Value.(*ast.Ident); !isIdent || v.Name != "nil" {
									legacyKey = true
								}
							}
						}
					}
				}
			case *ast.CallExpr:
				if sel, ok := x.Fun.(*ast.SelectorExpr); ok && sel.Sel.Name == "WithLegacyHeaders" && len(x.Args) == 1 {
					withStore = true
				}
			}
			return true
		})
	}
	if !legacyKey {
		t.Error("no runtime Deps literal of this package sets Legacy to a leg lister: the legacy-header loops would be off")
	}
	if !withStore {
		t.Error("no call of WithLegacyHeaders(store): the leg source would never read a reconstructed header")
	}
}
