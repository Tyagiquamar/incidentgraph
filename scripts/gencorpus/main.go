// Command gencorpus regenerates the synthetic incident corpora under
// datasets/incidents/. Every scenario ships correlated evidence (logs,
// metrics, deployment record, commit diff) whose ROOT CAUSE never appears
// verbatim in a single file — the agent must correlate across sources.
//
//	go run ./scripts/gencorpus
package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

type fileSpec struct {
	Path       string `json:"path"`
	SourceType string `json:"source_type"`
	File       string `json:"file"`
	Trust      string `json:"trust"`
}

type manifest struct {
	Incident struct {
		Slug     string `json:"slug"`
		Title    string `json:"title"`
		Service  string `json:"service"`
		Severity string `json:"severity"`
	} `json:"incident"`
	Files []fileSpec `json:"files"`
}

type scenario struct {
	slug, title, service, severity string
	logLines                       []string // written to logs/<svc>/<slug>.log
	metricSeries                   string   // symptom series name
	metricPoints                   [][2]any
	metricNote                     string // keyword-rich note (corroboration)
	p99Note                        string // generic latency note (secondary signal)
	deployLine                     string // deployments/<svc>/<commit>
	diffLine                       string // commits/<svc>/<commit>
}

func main() {
	scenarios := allScenarios()
	root := "datasets/incidents"
	if err := os.MkdirAll(root, 0o755); err != nil {
		panic(err)
	}
	for _, sc := range scenarios {
		dir := filepath.Join(root, sc.slug)
		if err := os.MkdirAll(dir, 0o755); err != nil {
			panic(err)
		}
		write(filepath.Join(dir, "manifest.json"), mustManifest(sc))
		write(filepath.Join(dir, "service.log"), joinLines(sc.logLines))
		write(filepath.Join(dir, "metrics_symptom.json"), metricJSON(sc.metricSeries, sc.metricPoints, sc.metricNote))
		write(filepath.Join(dir, "metrics_p99.json"), metricJSON("p99_latency_ms",
			[][2]any{{"09:00", 180}, {"10:00", 950}, {"11:00", 2600}},
			orDefault(sc.p99Note, "p99 latency elevated during the incident window")))
		write(filepath.Join(dir, "deployment.txt"), sc.deployLine)
		write(filepath.Join(dir, "diff.txt"), sc.diffLine)
		fmt.Println("wrote", sc.slug)
	}
	fmt.Printf("%d scenarios regenerated\n", len(scenarios))
}

func mustManifest(sc scenario) string {
	m := manifest{}
	m.Incident.Slug, m.Incident.Title = sc.slug, sc.title
	m.Incident.Service, m.Incident.Severity = sc.service, sc.severity
	commit := commitHash(sc.deployLine)
	m.Files = []fileSpec{
		{Path: "logs/" + sc.service + "/2026-08-23.log", SourceType: "log", File: "service.log", Trust: "tool_output"},
		{Path: "metrics/" + sc.service + "/" + sc.metricSeries, SourceType: "metrics", File: "metrics_symptom.json", Trust: "tool_output"},
		{Path: "metrics/" + sc.service + "/p99_latency_ms", SourceType: "metrics", File: "metrics_p99.json", Trust: "tool_output"},
		{Path: "deployments/" + sc.service + "/" + commit, SourceType: "deployment", File: "deployment.txt", Trust: "internal_document"},
		{Path: "commits/" + sc.service + "/" + commit, SourceType: "git_diff", File: "diff.txt", Trust: "internal_document"},
	}
	b, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		panic(err)
	}
	return string(b)
}

func commitHash(deployLine string) string {
	// deployLine convention: "... commit <hash> ..."
	const marker = " commit "
	i := indexOf(deployLine, marker)
	if i < 0 {
		return "unknown1"
	}
	rest := deployLine[i+len(marker):]
	if j := indexOf(rest, " "); j > 0 {
		return rest[:j]
	}
	return rest
}

func metricJSON(series string, points [][2]any, note string) string {
	type point struct {
		T string      `json:"t"`
		V interface{} `json:"v"`
	}
	out := struct {
		Series string  `json:"series"`
		Points []point `json:"points"`
		Note   string  `json:"note"`
	}{Series: series, Note: note}
	for _, p := range points {
		out.Points = append(out.Points, point{T: fmt.Sprint(p[0]), V: p[1]})
	}
	b, _ := json.MarshalIndent(out, "", " ")
	return string(b)
}

func joinLines(lines []string) string {
	out := ""
	for _, l := range lines {
		out += l + "\n"
	}
	return out
}

func write(path, content string) {
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		panic(err)
	}
}

func orDefault(v, def string) string {
	if v == "" {
		return def
	}
	return v
}

func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}
