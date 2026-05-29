// add_plusbuild walks a directory tree and adds // +build lines to .go files
// that only have //go:build constraints. This makes them parseable by Go < 1.17.
//
// Usage: go run scripts/add_plusbuild.go <dir>
package main

import (
	"bytes"
	"fmt"
	"go/build/constraint"
	"os"
	"path/filepath"
	"strings"
)

func main() {
	root := os.Args[1]
	var fixed int
	filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() || !strings.HasSuffix(path, ".go") {
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return nil
		}
		if !bytes.Contains(data, []byte("//go:build ")) {
			return nil
		}
		if bytes.Contains(data, []byte("// +build ")) {
			return nil
		}
		lines := bytes.SplitN(data, []byte("\n"), 40)
		for i, line := range lines {
			s := strings.TrimSpace(string(line))
			if !strings.HasPrefix(s, "//go:build ") {
				continue
			}
			expr, err := constraint.Parse(s)
			if err != nil {
				break
			}
			plusBuild := "// +build " + toLegacy(expr)
			insert := string(line) + "\n" + plusBuild
			lines[i] = []byte(insert)
			os.WriteFile(path, bytes.Join(lines, []byte("\n")), info.Mode())
			fixed++
			break
		}
		return nil
	})
	fmt.Printf("added // +build to %d files\n", fixed)
}

func toLegacy(expr constraint.Expr) string {
	switch e := expr.(type) {
	case *constraint.TagExpr:
		return e.Tag
	case *constraint.NotExpr:
		return "!" + toLegacy(e.X)
	case *constraint.AndExpr:
		return toLegacy(e.X) + "," + toLegacy(e.Y)
	case *constraint.OrExpr:
		return toLegacy(e.X) + " " + toLegacy(e.Y)
	default:
		return ""
	}
}
