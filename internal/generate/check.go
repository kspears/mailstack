package generate

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// Read loads the generated files from a generation directory.
func Read(dir string) (Files, error) {
	files := Files{}
	for _, name := range fileNames {
		b, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			return nil, err
		}
		files[name] = string(b)
	}
	return files, nil
}

// SelfCheck re-reads a written generation and verifies it is exactly the files
// that were rendered, and that each is newline-terminated or empty. What the
// files mean is checked by validate.Consistency before anything is rendered.
func SelfCheck(dir string, want Files) error {
	got, err := Read(dir)
	if err != nil {
		return fmt.Errorf("self-check: %w", err)
	}
	if !got.Equal(want) {
		return errors.New("self-check: the generation on disk is not what was rendered")
	}
	for _, name := range fileNames {
		if content := got[name]; content != "" && !strings.HasSuffix(content, "\n") {
			return fmt.Errorf("self-check: %s is not newline-terminated", name)
		}
	}
	return nil
}
