package pyimport

import (
	"bufio"
	"io"
	"regexp"
	"strings"
)

// callPattern matches "identifier.method(" or "identifier(" patterns.
// Group 1: optional receiver (may be empty), Group 2: function name.
var callPattern = regexp.MustCompile(`\b([A-Za-z_][A-Za-z0-9_]*)\.([A-Za-z_][A-Za-z0-9_]*)\s*\(|(?:^|[^.\w])([A-Za-z_][A-Za-z0-9_]*)\s*\(`)

// ParseSource parses a Python source file line-by-line and returns all import
// statements and crypto-relevant function calls. packageName is the dotted
// Python package name derived from the file's location (used for resolving
// relative imports). r is the content reader.
func ParseSource(filePath, packageName string, r io.Reader) (*FileImports, error) {
	fi := &FileImports{
		Path:    filePath,
		Package: packageName,
	}

	// aliasMap maps local name → fully-qualified module path.
	// e.g. "hl" → "hashlib", "SHA256" → "cryptography.hazmat.primitives.hashes.SHA256"
	aliasMap := map[string]string{}

	scanner := bufio.NewScanner(r)
	lineNum := 0
	inTripleQuote := false
	// multiLine state: when we see "from X import (" we collect names until ")"
	inMultiLine := false
	var multiLineImport *ImportInfo

	for scanner.Scan() {
		line := scanner.Text()
		lineNum++

		// Track triple-quoted strings (both """ and ''').
		// Count occurrences to toggle state.
		tripleDouble := strings.Count(line, `"""`)
		tripleSingle := strings.Count(line, `'''`)
		toggles := tripleDouble + tripleSingle
		if toggles > 0 {
			// If currently in a triple-quote block.
			if inTripleQuote {
				// Check if it closes on this line (odd number of markers).
				if toggles%2 == 1 {
					inTripleQuote = false
				}
				continue
			}
			// Not in triple-quote, check if we enter one.
			if toggles%2 == 1 {
				// Odd number means we open (and don't close on same line).
				inTripleQuote = true
				continue
			}
			// Even number: opens and closes on same line, treat as string literal, skip content.
			continue
		}
		if inTripleQuote {
			continue
		}

		// Handle multi-line import continuation.
		if inMultiLine {
			// Strip inline comment.
			content := stripInlineComment(line)
			// Check for closing paren.
			if idx := strings.Index(content, ")"); idx >= 0 {
				content = content[:idx]
				inMultiLine = false
			}
			names := parseNameList(content)
			for _, n := range names {
				name, alias := splitNameAlias(n)
				if alias != "" {
					// from X import Name as Z → aliasMap[Z] = X.Name
					aliasMap[alias] = multiLineImport.Module + "." + name
					multiLineImport.Names = append(multiLineImport.Names, name)
					// Store alias on the import if it's a single name alias.
					if len(multiLineImport.Names) == 1 {
						multiLineImport.Alias = alias
					}
				} else if name != "" {
					multiLineImport.Names = append(multiLineImport.Names, name)
					aliasMap[name] = multiLineImport.Module + "." + name
				}
			}
			if !inMultiLine {
				// Finalize the import.
				fi.Imports = append(fi.Imports, *multiLineImport)
				multiLineImport = nil
			}
			continue
		}

		trimmed := strings.TrimSpace(line)

		// Skip comment lines.
		if strings.HasPrefix(trimmed, "#") {
			continue
		}

		// Strip inline comments for parsing purposes.
		parseable := stripInlineComment(trimmed)

		if isImportLine(parseable) {
			imps := parseImportLine(parseable, packageName, lineNum, aliasMap)
			if imps != nil {
				for i := range imps {
					imp := &imps[i]
					// Check if multi-line (ends with open paren, no close paren).
					if imp == nil {
						continue
					}
					fi.Imports = append(fi.Imports, *imp)
				}
			}
			// Check for multi-line: the raw parseable ends with "(" without ")"
			// This is handled below via multiLineImport being set.
			// Re-check: if last import has open paren.
			if strings.Contains(parseable, "(") && !strings.Contains(parseable, ")") {
				// This is a multi-line import. Remove the last appended import
				// (it was partially parsed) and switch to multi-line mode.
				if len(fi.Imports) > 0 {
					last := fi.Imports[len(fi.Imports)-1]
					fi.Imports = fi.Imports[:len(fi.Imports)-1]
					// Re-remove aliases added during the partial parse so we can redo them.
					// Just set up multiLineImport; we'll re-add aliases as lines come in.
					multiLineImport = &ImportInfo{
						Module: last.Module,
						Names:  last.Names,
						Alias:  last.Alias,
						Line:   last.Line,
					}
					// Re-register aliases for already-found names.
					for _, n := range multiLineImport.Names {
						aliasMap[n] = multiLineImport.Module + "." + n
					}
					inMultiLine = true
				}
			}
		} else {
			// Scan for function calls.
			calls := extractCalls(parseable, aliasMap, lineNum)
			fi.Calls = append(fi.Calls, calls...)
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return fi, nil
}

// isImportLine returns true if a trimmed line starts with "import" or "from".
func isImportLine(line string) bool {
	return strings.HasPrefix(line, "import ") || strings.HasPrefix(line, "from ")
}

// parseImportLine parses a single import statement (possibly "import a, b, c"
// or "from X import Y" or "from X import (Y, Z)") and updates aliasMap.
// It returns one ImportInfo per logical import.
func parseImportLine(line, packageName string, lineNum int, aliasMap map[string]string) []ImportInfo {
	if strings.HasPrefix(line, "import ") {
		return parseBarImport(line, lineNum, aliasMap)
	}
	if strings.HasPrefix(line, "from ") {
		imp := parseFromImport(line, packageName, lineNum, aliasMap)
		if imp != nil {
			return []ImportInfo{*imp}
		}
	}
	return nil
}

// parseBarImport handles "import X" and "import X, Y, Z" and "import X as Y".
func parseBarImport(line string, lineNum int, aliasMap map[string]string) []ImportInfo {
	rest := strings.TrimPrefix(line, "import ")
	parts := strings.Split(rest, ",")
	var result []ImportInfo
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		name, alias := splitNameAlias(part)
		name = strings.TrimSpace(name)
		if name == "" {
			continue
		}
		imp := ImportInfo{Module: name, Line: lineNum}
		if alias != "" {
			imp.Alias = alias
			aliasMap[alias] = name
		} else {
			aliasMap[name] = name
		}
		result = append(result, imp)
	}
	return result
}

// parseFromImport handles "from X import Y [as Z]" and "from X import (Y, Z)".
func parseFromImport(line, packageName string, lineNum int, aliasMap map[string]string) *ImportInfo {
	// Remove "from " prefix.
	rest := strings.TrimPrefix(line, "from ")

	// Find " import ".
	idx := strings.Index(rest, " import ")
	if idx < 0 {
		return nil
	}

	modulePart := strings.TrimSpace(rest[:idx])
	namesPart := strings.TrimSpace(rest[idx+len(" import "):])

	// Resolve module (handles relative imports like ".", "..", "..crypto").
	module := resolveRelativeModule(modulePart, packageName)

	imp := &ImportInfo{
		Module: module,
		Line:   lineNum,
	}

	// Strip parens if present (for single-line "from X import (Y, Z)").
	namesPart = strings.TrimPrefix(namesPart, "(")
	namesPart = strings.TrimSuffix(namesPart, ")")

	names := parseNameList(namesPart)
	for _, n := range names {
		name, alias := splitNameAlias(n)
		name = strings.TrimSpace(name)
		if name == "" {
			continue
		}
		imp.Names = append(imp.Names, name)
		if alias != "" {
			// "from X import Name as Z" → aliasMap[Z] = X.Name, store alias.
			aliasMap[alias] = module + "." + name
			imp.Alias = alias // Store on ImportInfo (last alias wins for multi-name; typically single).
		} else {
			aliasMap[name] = module + "." + name
		}
	}

	return imp
}

// resolveRelativeModule resolves a dotted module spec including relative imports
// (leading dots) into an absolute module name using packageName as the anchor.
// "." → packageName, ".." → parent of packageName, "..X" → parent + ".X".
func resolveRelativeModule(modulePart, packageName string) string {
	if !strings.HasPrefix(modulePart, ".") {
		return modulePart
	}

	// Count leading dots.
	dots := 0
	for dots < len(modulePart) && modulePart[dots] == '.' {
		dots++
	}
	suffix := modulePart[dots:] // part after dots, e.g. "crypto" in "..crypto"

	// Navigate up from packageName by (dots - 1) levels.
	parts := strings.Split(packageName, ".")
	levels := dots - 1
	if levels >= len(parts) {
		// Gone past root; return suffix or empty.
		if suffix != "" {
			return suffix
		}
		return ""
	}
	base := parts[:len(parts)-levels]
	baseStr := strings.Join(base, ".")

	if suffix == "" {
		return baseStr
	}
	return baseStr + "." + suffix
}

// parseNameList splits a comma-separated list of import names, trimming spaces.
func parseNameList(s string) []string {
	parts := strings.Split(s, ",")
	var result []string
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			result = append(result, p)
		}
	}
	return result
}

// splitNameAlias splits "Name as Alias" into ("Name", "Alias").
// If there is no "as", returns (s, "").
func splitNameAlias(s string) (name, alias string) {
	s = strings.TrimSpace(s)
	// Case-sensitive " as " keyword.
	if idx := strings.Index(s, " as "); idx >= 0 {
		return strings.TrimSpace(s[:idx]), strings.TrimSpace(s[idx+4:])
	}
	return s, ""
}

// stripInlineComment removes an inline "#" comment and any trailing whitespace.
// It is a simple heuristic: find first unquoted "#".
func stripInlineComment(line string) string {
	inSingle := false
	inDouble := false
	for i, ch := range line {
		switch ch {
		case '\'':
			if !inDouble {
				inSingle = !inSingle
			}
		case '"':
			if !inSingle {
				inDouble = !inDouble
			}
		case '#':
			if !inSingle && !inDouble {
				return strings.TrimRight(line[:i], " \t")
			}
		}
	}
	return line
}

// extractCalls scans a non-import line for "receiver.method(" or "name(" patterns
// and resolves them via aliasMap.
func extractCalls(line string, aliasMap map[string]string, lineNum int) []FunctionCall {
	var calls []FunctionCall

	// Find all "X.Y(" patterns.
	matches := callPattern.FindAllStringSubmatchIndex(line, -1)
	for _, m := range matches {
		if m[2] >= 0 && m[4] >= 0 {
			// "receiver.method(" match: group 1=receiver, group 2=method.
			receiver := line[m[2]:m[3]]
			method := line[m[4]:m[5]]
			fullPath := resolveCall(receiver, method, aliasMap)
			if fullPath != "" {
				calls = append(calls, FunctionCall{
					Receiver: receiver,
					Name:     method,
					FullPath: fullPath,
					Line:     lineNum,
				})
			}
		} else if m[6] >= 0 {
			// "name(" match (no receiver): group 3=name.
			name := line[m[6]:m[7]]
			if resolved, ok := aliasMap[name]; ok {
				// Only record if it resolves to something with a dot (i.e. a real path).
				if strings.Contains(resolved, ".") {
					calls = append(calls, FunctionCall{
						Receiver: "",
						Name:     name,
						FullPath: resolved,
						Line:     lineNum,
					})
				}
			}
		}
	}
	return calls
}

// resolveCall resolves a "receiver.method" call using the alias map.
// Returns "" if the receiver is not in the alias map.
func resolveCall(receiver, method string, aliasMap map[string]string) string {
	if base, ok := aliasMap[receiver]; ok {
		return base + "." + method
	}
	// receiver not known → not a tracked import.
	return ""
}
