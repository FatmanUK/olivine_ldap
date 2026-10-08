package schema

import (
	"bufio"
	"io"
	"strings"
)

// splitDefs gathers the file into one string per definition.
//
// A definition starts at a line that begins in column zero and
// continues through every following indented line.
func splitDefs(src io.Reader) []string {
	var defs []string
	var cur strings.Builder
	sc := bufio.NewScanner(src)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		line := stripComment(sc.Text())
		if strings.TrimSpace(line) == "" {
			continue
		}
		if !isIndented(line) && cur.Len() > 0 {
			defs = append(defs, cur.String())
			cur.Reset()
		}
		cur.WriteString(" ")
		cur.WriteString(strings.TrimSpace(line))
	}
	if cur.Len() > 0 {
		defs = append(defs, cur.String())
	}
	return defs
}

// isIndented reports whether a line is a continuation.
func isIndented(line string) bool {
	return strings.HasPrefix(line, " ") ||
		strings.HasPrefix(line, "\t")
}

// stripComment removes a # comment.
//
// A # inside a quoted string is not a comment, which matters
// for DESC strings.
func stripComment(line string) string {
	inQuote := false
	for i := 0; i < len(line); i++ {
		switch line[i] {
		case '\'':
			inQuote = !inQuote
		case '#':
			if !inQuote {
				return line[:i]
			}
		}
	}
	return line
}
