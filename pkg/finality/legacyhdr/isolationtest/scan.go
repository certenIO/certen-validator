// Copyright 2026 Certen Protocol

package isolationtest

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

var itemShape = regexp.MustCompile(`^[a-z0-9_-]+(/[a-z0-9_/-]*)?$`)

// Undeclared walks the non-test Go sources under root (pkg/finality) and returns every capture item name or item prefix defined there
// that ProductionItems (production) does not cover, as "<candidate> (<file>)". A candidate is covered when it and a production entry
// are prefixes of one another in either direction. The scan is deliberately loose, so that a family added to the code without being
// added to ProductionItems fails the isolation test instead of going unguarded:
//
//   - a string constant or variable whose name contains "item" (any value) or "prefix" (a value with a "/"), in any case, other than the
//     Reason*, Code* and Pins* tokens of the closed sets: ItemHeader = "header", ItemPrefix = "gap/", itemTxPre = "tx/",
//     captureItemState = "arbfinal/state/";
//   - a function whose name starts with "Item" and whose body holds a string literal: the literal up to its first format verb
//     (ItemBatch -> "batch/", ItemDelayedProof -> "delayedproof/");
//   - a composite literal with a field Item set to a string literal.
//
// The directories testdata and legacyhdr (the legacy item itself) are not scanned.
func Undeclared(root string, production []string) ([]string, error) {
	found := map[string]string{}
	add := func(lit, file string) {
		lit = strings.TrimSpace(lit)
		if i := strings.IndexByte(lit, '%'); i >= 0 {
			lit = lit[:i]
		}
		if lit == "" || !itemShape.MatchString(lit) {
			return
		}
		if _, ok := found[lit]; !ok {
			found[lit] = file
		}
	}
	str := func(e ast.Expr) (string, bool) {
		bl, ok := e.(*ast.BasicLit)
		if !ok || bl.Kind != token.STRING {
			return "", false
		}
		s, err := strconv.Unquote(bl.Value)
		return s, err == nil
	}
	fset := token.NewFileSet()
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if n := d.Name(); n == "testdata" || n == "legacyhdr" {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		file, err := parser.ParseFile(fset, path, nil, 0)
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(root, path)
		ast.Inspect(file, func(n ast.Node) bool {
			switch x := n.(type) {
			case *ast.ValueSpec:
				for i, name := range x.Names {
					if i >= len(x.Values) {
						continue
					}
					lit, ok := str(x.Values[i])
					if !ok {
						continue
					}
					low := strings.ToLower(name.Name)
					if strings.HasPrefix(name.Name, "Reason") || strings.HasPrefix(name.Name, "Code") || strings.HasPrefix(name.Name, "Pins") {
						continue // closed-set reason tokens (ReasonHeaderBadItem = "header_bad_item"), not capture items
					}
					switch {
					case strings.Contains(low, "item"):
						add(lit, filepath.ToSlash(rel))
					case strings.Contains(low, "prefix") && strings.Contains(lit, "/"):
						add(lit, filepath.ToSlash(rel))
					}
				}
			case *ast.FuncDecl:
				if x.Body != nil && strings.HasPrefix(x.Name.Name, "Item") {
					ast.Inspect(x.Body, func(m ast.Node) bool {
						if lit, ok := m.(*ast.BasicLit); ok {
							if s, ok := str(lit); ok {
								add(s, filepath.ToSlash(rel))
							}
						}
						return true
					})
				}
			case *ast.KeyValueExpr:
				if k, ok := x.Key.(*ast.Ident); ok && k.Name == "Item" {
					if s, ok := str(x.Value); ok {
						add(s, filepath.ToSlash(rel))
					}
				}
			}
			return true
		})
		return nil
	})
	if err != nil {
		return nil, err
	}
	var missing []string
	for lit, file := range found {
		covered := false
		for _, p := range production {
			if strings.HasPrefix(lit, p) || strings.HasPrefix(p, lit) {
				covered = true
				break
			}
		}
		if !covered {
			missing = append(missing, fmt.Sprintf("%s (%s)", lit, file))
		}
	}
	sort.Strings(missing)
	return missing, nil
}
