package retrieval

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// Chunk is the unit produced by structure-aware chunking.
type Chunk struct {
	Content    string
	ChunkIndex int
	Metadata   map[string]any // heading path, timestamp range, symbol name...
}

const approxCharsPerToken = 4

// ApproxTokens estimates token count cheaply.
func ApproxTokens(s string) int { return (len(s) + approxCharsPerToken - 1) / approxCharsPerToken }

type ChunkOptions struct {
	MaxTokens   int // soft max per chunk (default ~320)
	ServiceName string
	Timestamp   string
}

// ChunkDocument dispatches on source type to a structure-aware chunker.
func ChunkDocument(sourceType, content string, opts ChunkOptions) []Chunk {
	if opts.MaxTokens <= 0 {
		opts.MaxTokens = 320
	}
	var chunks []Chunk
	switch sourceType {
	case "markdown", "runbook", "postmortem":
		chunks = chunkMarkdown(content, opts)
	case "source_code":
		chunks = chunkSource(content, opts)
	case "log":
		chunks = chunkLogs(content, opts)
	default:
		chunks = chunkParagraphs(content, opts)
	}
	for i := range chunks {
		chunks[i].ChunkIndex = i
		if chunks[i].Metadata == nil {
			chunks[i].Metadata = map[string]any{}
		}
		if opts.ServiceName != "" {
			chunks[i].Metadata["service"] = opts.ServiceName
		}
		if opts.Timestamp != "" {
			chunks[i].Metadata["timestamp"] = opts.Timestamp
		}
		chunks[i].Metadata["chunk_index"] = i
	}
	return chunks
}

var mdHeadingRe = regexp.MustCompile(`(?m)^#{1,6}\s+(.+)$`)

// chunkMarkdown splits by headings. Headings are hard semantic boundaries:
// each section becomes its own chunk so citations can point at an exact
// runbook/postmortem section; only oversized sections are paragraph-split.
func chunkMarkdown(content string, opts ChunkOptions) []Chunk {
	lines := strings.Split(content, "\n")
	type section struct {
		heading string
		body    strings.Builder
	}
	var sections []section
	cur := section{}
	for _, ln := range lines {
		if m := mdHeadingRe.FindStringSubmatch(ln); m != nil {
			sections = append(sections, cur)
			cur = section{heading: strings.TrimSpace(m[1])}
			continue
		}
		cur.body.WriteString(ln)
		cur.body.WriteString("\n")
	}
	sections = append(sections, cur)

	var out []Chunk
	emit := func(heading, body string) {
		s := strings.TrimSpace(body)
		if s == "" && heading == "" {
			return
		}
		md := map[string]any{"structure": "markdown_section"}
		if heading != "" {
			md["heading"] = heading
		}
		out = append(out, Chunk{Content: s, Metadata: md})
	}
	for _, sec := range sections {
		full := sec.heading + "\n" + sec.body.String()
		if ApproxTokens(full) > opts.MaxTokens {
			for _, p := range splitParas(strings.TrimSpace(sec.body.String()), opts.MaxTokens) {
				emit(sec.heading, p)
			}
			continue
		}
		emit(sec.heading, full)
	}
	return out
}

var codeBlockStartRe = regexp.MustCompile(`(?m)^(func|fn|def|class|impl|pub|export|async)\b|^(\w+)\s*\(\)\s*\{|^\}`)

func chunkSource(content string, opts ChunkOptions) []Chunk {
	lines := strings.Split(content, "\n")
	var out []Chunk
	buf := strings.Builder{}
	startLine := 0
	flush := func(endLine int) {
		s := strings.TrimSpace(buf.String())
		if s == "" {
			return
		}
		out = append(out, Chunk{Content: s, Metadata: map[string]any{
			"structure":   "code_block",
			"symbol_hint": symbolHint(s),
			"lines":       fmt.Sprintf("%d-%d", startLine+1, endLine),
		}})
		buf.Reset()
	}
	for i, ln := range lines {
		isBoundary := codeBlockStartRe.MatchString(ln)
		if isBoundary && ApproxTokens(buf.String())+ApproxTokens(ln) > opts.MaxTokens {
			flush(i)
			startLine = i
		}
		buf.WriteString(ln)
		buf.WriteString("\n")
	}
	flush(len(lines))
	return out
}

func symbolHint(block string) string {
	for _, ln := range strings.Split(block, "\n") {
		t := strings.TrimSpace(ln)
		if t == "" {
			continue
		}
		if len(t) > 80 {
			t = t[:80]
		}
		return t
	}
	return ""
}

var logTSRe = regexp.MustCompile(`^(\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2})|\[(\w{3}\s+\d+\s+\d{2}:\d{2})`)

// chunkLogs groups log lines into temporal windows (~same minute cluster),
// falling back to fixed-size groups when timestamps are absent.
func chunkLogs(content string, opts ChunkOptions) []Chunk {
	lines := strings.Split(strings.TrimRight(content, "\n"), "\n")
	var out []Chunk
	var group []string
	groupKey := ""
	flush := func(meta string) {
		if len(group) == 0 {
			return
		}
		body := strings.Join(group, "\n")
		md := map[string]any{"structure": "log_group"}
		if meta != "" {
			md["time_window"] = meta
		}
		out = append(out, Chunk{Content: body, Metadata: md})
		group = nil
	}
	const maxLines = 60
	for _, ln := range lines {
		key := ""
		if m := logTSRe.FindStringSubmatch(ln); m != nil {
			key = coalesce(m[1], m[2])
			key = key[:min(len(key), 16)] // minute granularity
		}
		newGroup := key != "" && key != groupKey || ApproxTokens(strings.Join(group, ""))+ApproxTokens(ln) > opts.MaxTokens
		if len(group) > 0 && (newGroup || len(group) >= maxLines) {
			flush(groupKey)
		}
		if key != "" {
			groupKey = key
		}
		group = append(group, ln)
	}
	flush(groupKey)
	return out
}

func chunkParagraphs(content string, opts ChunkOptions) []Chunk {
	var out []Chunk
	for _, p := range splitParas(content, opts.MaxTokens) {
		out = append(out, Chunk{Content: p, Metadata: map[string]any{"structure": "paragraph"}})
	}
	return out
}

func splitParas(text string, maxTokens int) []string {
	paras := regexp.MustCompile(`\n\s*\n`).Split(text, -1)
	var out []string
	buf := strings.Builder{}
	flush := func() {
		s := strings.TrimSpace(buf.String())
		if s != "" {
			out = append(out, s)
		}
		buf.Reset()
	}
	for _, p := range paras {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		if ApproxTokens(p) > maxTokens {
			flush()
			// hard-split oversized paragraph on sentences/lines
			for _, piece := range hardSplit(p, maxTokens*approxCharsPerToken) {
				out = append(out, piece)
			}
			continue
		}
		if ApproxTokens(buf.String())+ApproxTokens(p) > maxTokens {
			flush()
		}
		buf.WriteString(p)
		buf.WriteString("\n\n")
	}
	flush()
	return out
}

func hardSplit(s string, maxChars int) []string {
	var out []string
	for len(s) > maxChars {
		cut := s[:maxChars]
		if idx := strings.LastIndexAny(cut, ".\n"); idx > maxChars/2 {
			cut = cut[:idx+1]
		}
		out = append(out, strings.TrimSpace(cut))
		s = s[len(cut):]
	}
	if t := strings.TrimSpace(s); t != "" {
		out = append(out, t)
	}
	return out
}

func coalesce(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

var _ = strconv.Itoa
