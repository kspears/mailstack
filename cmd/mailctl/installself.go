package main

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
)

// installSelf copies this binary into dir as "mailctl". The admin image is distroless,
// so a one-shot container running this is how another container, such as dovecot, whose
// image has no shell tools either, gets the static binary to use as a Sieve pipe program.
func (e *env) installSelf(args []string) error {
	if len(args) != 1 {
		return usageError("install-self <directory>")
	}
	exe, err := os.Executable()
	if err != nil {
		return fmt.Errorf("find this binary: %w", err)
	}
	src, err := os.Open(exe)
	if err != nil {
		return fmt.Errorf("open %s: %w", exe, err)
	}
	defer src.Close()
	tmp, err := os.CreateTemp(args[0], ".mailctl-")
	if err != nil {
		return fmt.Errorf("write to %s: %w", args[0], err)
	}
	defer os.Remove(tmp.Name())
	if _, err := io.Copy(tmp, src); err != nil {
		tmp.Close()
		return fmt.Errorf("copy %s: %w", exe, err)
	}
	if err := tmp.Chmod(0o755); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	dest := filepath.Join(args[0], "mailctl")
	if err := os.Rename(tmp.Name(), dest); err != nil {
		return fmt.Errorf("install %s: %w", dest, err)
	}
	fmt.Fprintln(e.stdout, "ok: installed "+dest)
	return nil
}
