package consensus

// C5-D1: no CometBFT configuration is built in this module without the transaction limits. Uses only symbols that
// exist at the base commit (the limits are named by string), so it fails there by behaviour.

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// Nothing may build a CometBFT configuration without the transaction limits: every function that calls
// config.DefaultConfig / config.TestConfig (or builds a config.Config) in this module - production builders and test
// networks alike - must apply them itself or hand the configuration to NewRealCometBFTEngine, which does.
func TestNoCometBFTConfigIsBuiltWithoutTheTransactionLimits(t *testing.T) {
	root := "../.."
	var bad, found []string
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			switch d.Name() {
			case ".git", "node_modules", "testdata", "vendor":
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") {
			return nil
		}
		fset := token.NewFileSet()
		// Imports first: only a file that imports CometBFT's config package can build one.
		head, err := parser.ParseFile(fset, path, nil, parser.ImportsOnly)
		if err != nil {
			return fmt.Errorf("%s: %w", path, err)
		}
		importsConfig := false
		for _, imp := range head.Imports {
			if p, _ := strconv.Unquote(imp.Path.Value); p == "github.com/cometbft/cometbft/config" {
				importsConfig = true
			}
		}
		if !importsConfig {
			return nil
		}
		f, err := parser.ParseFile(fset, path, nil, parser.SkipObjectResolution)
		if err != nil {
			return fmt.Errorf("%s: %w", path, err)
		}
		cometAliases := map[string]bool{}
		for _, imp := range f.Imports {
			if p, _ := strconv.Unquote(imp.Path.Value); p == "github.com/cometbft/cometbft/config" {
				name := "config"
				if imp.Name != nil {
					name = imp.Name.Name
				}
				cometAliases[name] = true
			}
		}
		if len(cometAliases) == 0 {
			return nil
		}
		for _, decl := range f.Decls {
			fd, ok := decl.(*ast.FuncDecl)
			if !ok || fd.Body == nil {
				continue
			}
			builds, applies := false, false
			ast.Inspect(fd.Body, func(n ast.Node) bool {
				switch x := n.(type) {
				case *ast.CallExpr:
					switch fn := x.Fun.(type) {
					case *ast.SelectorExpr:
						if id, ok := fn.X.(*ast.Ident); ok && cometAliases[id.Name] && (fn.Sel.Name == "DefaultConfig" || fn.Sel.Name == "TestConfig") {
							builds = true
						}
					case *ast.Ident:
						if fn.Name == "applyCometTxLimits" || fn.Name == "NewRealCometBFTEngine" {
							applies = true
						}
					}
				case *ast.CompositeLit:
					if se, ok := x.Type.(*ast.SelectorExpr); ok {
						if id, ok := se.X.(*ast.Ident); ok && cometAliases[id.Name] && se.Sel.Name == "Config" {
							builds = true
						}
					}
				}
				return true
			})
			if builds {
				site := fmt.Sprintf("%s:%s", filepath.ToSlash(path), fd.Name.Name)
				found = append(found, site)
				if !applies {
					bad = append(bad, site)
				}
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	sort.Strings(found)
	if len(found) < 5 {
		t.Fatalf("the scan found only %d config-building functions (%v); it is not reading the module", len(found), found)
	}
	if len(bad) > 0 {
		t.Fatalf("these functions build a CometBFT configuration without applyCometTxLimits (rpc.max_body_bytes then stays at "+
			"CometBFT's 1,000,000, below a base64-encoded max_tx_bytes): %v", bad)
	}
}
