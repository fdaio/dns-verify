package main

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// workflowcheck reports a workflow file GitHub would reject before any job
// runs: a job that depends on itself, or on a job that is not there.
//
// Nothing in a build catches this, because the file is valid YAML and the error
// only appears when the workflow graph is built. A release failed that way once:
// a matrix job kept the name of the job it replaced and so depended on itself.
func main() {
	dir := ".github/workflows"
	entries, err := os.ReadDir(dir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "workflowcheck: read %s: %v\n", dir, err)
		os.Exit(1)
	}

	problems := 0
	for _, entry := range entries {
		if !strings.HasSuffix(entry.Name(), ".yml") {
			continue
		}
		for _, p := range check(filepath.Join(dir, entry.Name())) {
			fmt.Fprintf(os.Stderr, "workflowcheck: %s\n", p)
			problems++
		}
	}
	if problems > 0 {
		os.Exit(1)
	}
}

// check returns every way the job graph in one file would be rejected.
func check(path string) []string {
	data, err := os.ReadFile(path)
	if err != nil {
		return []string{fmt.Sprintf("%s: %v", path, err)}
	}

	var (
		problems   []string
		declared   []string
		referenced = map[string]bool{}
		current    string
		seenJob    bool
	)

	for _, line := range strings.Split(string(data), "\n") {
		if job, ok := jobHeader(line); ok {
			if seenJob {
				declared = append(declared, current)
			}
			current, seenJob = job, true
			continue
		}
		deps, ok := needsOf(line)
		if !ok || !seenJob {
			continue
		}
		for _, dep := range deps {
			if dep == current {
				problems = append(problems,
					fmt.Sprintf("%s: job %q depends on itself", path, current))
				continue
			}
			referenced[dep] = true
		}
	}
	if seenJob {
		declared = append(declared, current)
	}

	if len(declared) == 0 {
		return []string{fmt.Sprintf("%s: no jobs found, the parser is wrong", path)}
	}

	known := make(map[string]bool, len(declared))
	for _, job := range declared {
		known[job] = true
	}
	for dep := range referenced {
		if !known[dep] {
			problems = append(problems,
				fmt.Sprintf("%s: a job depends on %q, which is not declared", path, dep))
		}
	}
	return problems
}

// jobHeaderRe matches a two-space indented "name:" that starts a job.
var jobHeaderRe = regexp.MustCompile(`^ {2}([a-zA-Z0-9_-]+):\s*$`)

// needsRe matches an indented "needs: [a, b]" or "needs: a" line.
var needsRe = regexp.MustCompile(`^\s{4,}needs:\s*\[?([^\]]*)\]?\s*$`)

// topLevel are keys that sit beside jobs without being one.
var topLevel = map[string]bool{
	"on": true, "permissions": true, "env": true, "defaults": true, "concurrency": true,
}

func jobHeader(line string) (string, bool) {
	m := jobHeaderRe.FindStringSubmatch(line)
	if m == nil || topLevel[m[1]] {
		return "", false
	}
	return m[1], true
}

func needsOf(line string) ([]string, bool) {
	m := needsRe.FindStringSubmatch(line)
	if m == nil {
		return nil, false
	}
	var out []string
	for _, dep := range strings.Split(m[1], ",") {
		if dep = strings.TrimSpace(dep); dep != "" {
			out = append(out, dep)
		}
	}
	return out, len(out) > 0
}
