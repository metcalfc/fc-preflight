// Copyright 2026 Fly.io. Apache-2.0.

package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"time"
)

// Status is the outcome of a single check.
//
// The distinction that matters is Fail vs Warn. Fail means a Firecracker
// microVM as Fly runs it will not work correctly on this host, and no amount
// of configuration on our side changes that. Warn means it will work but
// something about it is worse than a Fly host today -- usually performance, or
// a knob that wants setting. Info is a measurement with no pass/fail opinion,
// recorded so the two sides can diff a candidate host against a reference one.
type Status string

const (
	Pass Status = "pass"
	Fail Status = "fail"
	Warn Status = "warn"
	Info Status = "info"
	Skip Status = "skip"
)

// Result is one check.
type Result struct {
	ID     string         `json:"id"`
	Title  string         `json:"title"`
	Status Status         `json:"status"`
	Detail string         `json:"detail,omitempty"`
	Data   map[string]any `json:"data,omitempty"`
	// Remedy is what to do about a fail or a warn. Empty for pass and info.
	Remedy string `json:"remedy,omitempty"`
}

// Report is the whole run. This is the artifact that gets sent back: it is
// designed to be diffed against a run on a known-good Fly host, so it records
// measurements even where there is nothing to assert.
type Report struct {
	Schema    string         `json:"schema"`
	Tool      string         `json:"tool"`
	StartedAt time.Time      `json:"started_at"`
	Duration  string         `json:"duration"`
	Hostname  string         `json:"hostname"`
	Verdict   Status         `json:"verdict"`
	Summary   map[Status]int `json:"summary"`
	Results   []Result       `json:"results"`

	start time.Time
}

func NewReport() *Report {
	h, _ := os.Hostname()
	return &Report{
		Schema:    "fly.fc-preflight/v1",
		Tool:      version,
		StartedAt: time.Now().UTC(),
		Hostname:  h,
		start:     time.Now(),
	}
}

func (r *Report) Add(res Result) {
	r.Results = append(r.Results, res)
	if *flagVerbose {
		fmt.Fprintln(os.Stderr, renderOne(res))
	}
}

// Addf is the common case: a check with a formatted detail string.
func (r *Report) Addf(id, title string, st Status, format string, args ...any) {
	r.Add(Result{ID: id, Title: title, Status: st, Detail: fmt.Sprintf(format, args...)})
}

// Fail records a failure together with what to do about it. Every Fail should
// carry a remedy; a failure the operator cannot act on is a bug in this tool.
func (r *Report) Fail(id, title, detail, remedy string) {
	r.Add(Result{ID: id, Title: title, Status: Fail, Detail: detail, Remedy: remedy})
}

func (r *Report) Warn(id, title, detail, remedy string) {
	r.Add(Result{ID: id, Title: title, Status: Warn, Detail: detail, Remedy: remedy})
}

// Finish computes the verdict. Any Fail fails the run; warnings never do.
func (r *Report) Finish() {
	r.Duration = time.Since(r.start).Round(time.Millisecond).String()
	r.Summary = map[Status]int{}
	r.Verdict = Pass
	for _, res := range r.Results {
		r.Summary[res.Status]++
		if res.Status == Fail {
			r.Verdict = Fail
		}
	}
}

func (r *Report) WriteJSON(w io.Writer) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(r)
}

func renderOne(res Result) string {
	var mark string
	switch res.Status {
	case Pass:
		mark = "  ok  "
	case Fail:
		mark = " FAIL "
	case Warn:
		mark = " warn "
	case Info:
		mark = " info "
	case Skip:
		mark = " skip "
	}
	line := fmt.Sprintf("[%s] %-34s %s", mark, res.ID, res.Title)
	if res.Detail != "" {
		line += "\n" + indent(res.Detail, "                ")
	}
	if res.Remedy != "" {
		line += "\n" + indent("-> "+res.Remedy, "                ")
	}
	return line
}

func indent(s, pad string) string {
	lines := strings.Split(strings.TrimRight(s, "\n"), "\n")
	for i := range lines {
		lines[i] = pad + lines[i]
	}
	return strings.Join(lines, "\n")
}

// Render writes the human-readable report. Failures are repeated at the end,
// because the thing an operator needs off a long run is the short list of what
// is wrong, not a scroll back through what was fine.
func (r *Report) Render(w io.Writer) {
	fmt.Fprintf(w, "\nfc-preflight %s -- %s -- %s\n", r.Tool, r.Hostname, r.StartedAt.Format(time.RFC3339))
	fmt.Fprintf(w, "%s\n\n", strings.Repeat("=", 78))

	for _, res := range r.Results {
		fmt.Fprintln(w, renderOne(res))
	}

	fmt.Fprintf(w, "\n%s\n", strings.Repeat("=", 78))

	keys := []Status{Pass, Warn, Fail, Info, Skip}
	var parts []string
	for _, k := range keys {
		if n := r.Summary[k]; n > 0 {
			parts = append(parts, fmt.Sprintf("%d %s", n, k))
		}
	}
	fmt.Fprintf(w, "%s in %s\n", strings.Join(parts, ", "), r.Duration)

	var fails, warns []Result
	for _, res := range r.Results {
		switch res.Status {
		case Fail:
			fails = append(fails, res)
		case Warn:
			warns = append(warns, res)
		}
	}
	sort.SliceStable(fails, func(i, j int) bool { return fails[i].ID < fails[j].ID })

	if len(fails) > 0 {
		fmt.Fprintf(w, "\nBLOCKING -- a Fly microVM will not run correctly here:\n")
		for _, res := range fails {
			fmt.Fprintf(w, "  * %s: %s\n", res.ID, res.Detail)
			if res.Remedy != "" {
				fmt.Fprintf(w, "    %s\n", res.Remedy)
			}
		}
	}
	if len(warns) > 0 {
		fmt.Fprintf(w, "\nNON-BLOCKING -- works, but differs from a Fly host:\n")
		for _, res := range warns {
			fmt.Fprintf(w, "  * %s: %s\n", res.ID, res.Detail)
			if res.Remedy != "" {
				fmt.Fprintf(w, "    %s\n", res.Remedy)
			}
		}
	}

	fmt.Fprintf(w, "\nVERDICT: %s\n\n", strings.ToUpper(string(r.Verdict)))
}
