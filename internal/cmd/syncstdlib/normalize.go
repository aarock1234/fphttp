package main

import (
	"fmt"
	"go/ast"
	"go/format"
	"go/parser"
	"go/token"
	"slices"
	"strconv"
	"strings"
)

type sourceEdit struct {
	start       int
	end         int
	replacement string
}

// normalizeSource applies the same module-boundary adaptations to the base
// and incoming sources, so the merge operates on comparable files. Runtime
// aliases cannot be reused by a package with distinct exported Go types.
func normalizeSource(path string, source []byte) ([]byte, error) {
	lines := strings.Split(string(source), "\n")
	lines = slices.DeleteFunc(lines, func(line string) bool {
		return strings.HasPrefix(strings.TrimSpace(line), "//go:linkname ")
	})
	source = []byte(strings.Join(lines, "\n"))

	positions := token.NewFileSet()
	file, err := parser.ParseFile(positions, path, source, parser.ParseComments)
	if err != nil {
		return nil, err
	}
	var edits []sourceEdit
	edit := func(node ast.Node, replacement string) {
		start := node.Pos()
		switch node := node.(type) {
		case *ast.FuncDecl:
			if node.Doc != nil {
				start = node.Doc.Pos()
			}
		case *ast.GenDecl:
			if node.Doc != nil {
				start = node.Doc.Pos()
			}
		}
		edits = append(edits, sourceEdit{
			start:       positions.Position(start).Offset,
			end:         positions.Position(node.End()).Offset,
			replacement: replacement,
		})
	}

	ast.Inspect(file, func(node ast.Node) bool {
		switch node := node.(type) {
		case *ast.FuncDecl:
			switch node.Name.Name {
			case "badRoundTrip", "badServeHTTP", "transportFromH1Transport", "getErrChan", "putErrChan":
				edit(node, "")
				return false
			case "readMIMEHeader":
				if node.Body == nil {
					edit(node, "")
					return false
				}
			}
		case *ast.GenDecl:
			if node.Tok == token.IMPORT {
				edit(node, normalizedImports(node))
				return false
			}
			if node.Tok == token.VAR && len(node.Specs) == 1 {
				if declaration, ok := node.Specs[0].(*ast.ValueSpec); ok && len(declaration.Names) == 1 && declaration.Names[0].Name == "errChanPool" {
					edit(node, "")
					return false
				}
			}
		case *ast.ExprStmt:
			if call, ok := node.X.(*ast.CallExpr); ok {
				if name, ok := call.Fun.(*ast.Ident); ok && name.Name == "putErrChan" {
					edit(node, "")
					return false
				}
			}
		case *ast.CallExpr:
			if name, ok := node.Fun.(*ast.Ident); ok && name.Name == "getErrChan" && len(node.Args) == 0 {
				edit(node, "make(chan error, 1)")
				return false
			}
		}

		return true
	})
	slices.SortFunc(edits, func(a, b sourceEdit) int {
		return b.start - a.start
	})
	for _, edit := range edits {
		replacement := append([]byte(nil), source[:edit.start]...)
		replacement = append(replacement, edit.replacement...)
		source = append(replacement, source[edit.end:]...)
	}

	source, err = format.Source(source)
	if err != nil {
		return nil, fmt.Errorf("format adapted source: %w", err)
	}

	return source, nil
}

func normalizedImports(declaration *ast.GenDecl) string {
	var groups [4][]string
	for _, item := range declaration.Specs {
		spec := item.(*ast.ImportSpec)
		path, _ := strconv.Unquote(spec.Path.Value) // parser already checked the quoted literal
		if path == "internal/synctest" || (path == "unsafe" && spec.Name != nil && spec.Name.Name == "_") {
			continue
		}
		switch {
		case path == "net/http" || strings.HasPrefix(path, "net/http/"):
			path = modulePath + strings.TrimPrefix(path, "net/http")
		case path == "internal/godebug", path == "internal/profile", path == "internal/nettrace", path == "internal/goexperiment":
			path = modulePath + "/" + path
		}

		group := 0
		switch {
		case spec.Name != nil && spec.Name.Name == "_":
			group = 3
		case strings.HasPrefix(path, modulePath):
			group = 2
		case strings.Contains(strings.Split(path, "/")[0], "."):
			group = 1
		}
		line := "\t"
		if spec.Name != nil {
			line += spec.Name.Name + " "
		}
		groups[group] = append(groups[group], line+strconv.Quote(path))
	}

	var blocks []string
	for _, group := range groups {
		if len(group) > 0 {
			slices.Sort(group)
			blocks = append(blocks, strings.Join(group, "\n"))
		}
	}
	if len(blocks) == 0 {
		return ""
	}

	return "import (\n" + strings.Join(blocks, "\n\n") + "\n)"
}
