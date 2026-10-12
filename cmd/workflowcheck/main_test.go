package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A workflow is rejected before any job runs when one depends on itself, or on a
// job that does not exist. Nothing in a build catches that, because the file is
// valid YAML and the error appears only when the graph is built.
func TestRealWorkflowsAreValid(t *testing.T) {
	dir := filepath.Join("..", "..", ".github", "workflows")
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read %s: %v", dir, err)
	}

	found := 0
	for _, entry := range entries {
		if !strings.HasSuffix(entry.Name(), ".yml") {
			continue
		}
		found++
		t.Run(entry.Name(), func(t *testing.T) {
			if problems := check(filepath.Join(dir, entry.Name())); len(problems) > 0 {
				for _, p := range problems {
					t.Error(p)
				}
			}
		})
	}
	if found == 0 {
		t.Fatal("no workflows found, the test is not looking where it thinks")
	}
}

func TestCheckFindsSelfDependency(t *testing.T) {
	// The shape a release hit: a matrix job kept the name of the job it replaced.
	path := write(t, `
jobs:
  test:
    name: test (linux)
    needs: [ test ]
    runs-on: ubuntu-latest
    steps: []
  build:
    needs: [ test ]
    runs-on: ubuntu-latest
    steps: []
`)
	problems := check(path)
	if len(problems) == 0 {
		t.Fatal("a job depending on itself must be reported")
	}
	if !strings.Contains(problems[0], "depends on itself") {
		t.Errorf("problem = %q, want the self dependency", problems[0])
	}
}

func TestCheckFindsMissingDependency(t *testing.T) {
	path := write(t, `
jobs:
  build:
    needs: [ test ]
    runs-on: ubuntu-latest
    steps: []
`)
	problems := check(path)
	if len(problems) == 0 {
		t.Fatal("a dependency on an undeclared job must be reported")
	}
	if !strings.Contains(problems[0], "not declared") {
		t.Errorf("problem = %q, want the missing job", problems[0])
	}
}

func TestCheckAcceptsAValidGraph(t *testing.T) {
	path := write(t, `
jobs:
  test-platform:
    name: test (linux)
    runs-on: ubuntu-latest
    steps: []
  build:
    needs: [ test-platform ]
    runs-on: ubuntu-latest
    steps: []
  publish:
    needs: [ build ]
    runs-on: ubuntu-latest
    steps: []
`)
	if problems := check(path); len(problems) > 0 {
		t.Errorf("a valid graph was reported as broken: %v", problems)
	}
}

// "on" and "permissions" sit beside the jobs and must not be read as one.
func TestCheckIgnoresTopLevelKeys(t *testing.T) {
	path := write(t, `
on:
  push:
    tags: ["v*"]
permissions:
  contents: write
jobs:
  build:
    runs-on: ubuntu-latest
    steps: []
`)
	if problems := check(path); len(problems) > 0 {
		t.Errorf("top level keys were read as jobs: %v", problems)
	}
}

func write(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "workflow.yml")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	return path
}
