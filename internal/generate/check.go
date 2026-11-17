package generate

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/kspears/mailstack/internal/validate"
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

// SelfCheck re-reads a written generation and verifies it is well formed and
// internally consistent: every alias target resolves and no address is both
// a mailbox and an alias.
func SelfCheck(dir string) error {
	files, err := Read(dir)
	if err != nil {
		return fmt.Errorf("self-check: %w", err)
	}
	domains, err := parseMap(files, FileDomains, func(v string) bool { return v == "OK" })
	if err != nil {
		return err
	}
	mailboxes, err := parseMap(files, FileMailboxes, func(v string) bool { return v == "OK" })
	if err != nil {
		return err
	}
	aliases, err := parseMap(files, FileAliases, func(v string) bool { return v != "" && !strings.Contains(v, " ") })
	if err != nil {
		return err
	}
	if _, err := parseMap(files, FileSenderLogin, func(v string) bool { return v != "" && !strings.Contains(v, " ") }); err != nil {
		return err
	}
	if err := checkUsers(files[FileUsers], mailboxes); err != nil {
		return err
	}
	for m := range mailboxes {
		if _, dup := aliases[m]; dup {
			return fmt.Errorf("self-check: %s is both a mailbox and an alias", m)
		}
	}
	for a, v := range aliases {
		for _, t := range strings.Split(v, ",") {
			if _, err := validate.Address(t); err != nil {
				return fmt.Errorf("self-check: alias %s: %w", a, err)
			}
			_, d := validate.Split(t)
			if _, hosted := domains[d]; !hosted {
				continue
			}
			_, isMailbox := mailboxes[t]
			_, isAlias := aliases[t]
			if !isMailbox && !isAlias {
				return fmt.Errorf("self-check: alias %s targets %s, which does not resolve", a, t)
			}
		}
	}
	return nil
}

func parseMap(files Files, name string, validValue func(string) bool) (map[string]string, error) {
	out := map[string]string{}
	content := files[name]
	if content == "" {
		return out, nil
	}
	if !strings.HasSuffix(content, "\n") {
		return nil, fmt.Errorf("self-check: %s is not newline-terminated", name)
	}
	for _, line := range strings.Split(strings.TrimSuffix(content, "\n"), "\n") {
		key, value, ok := strings.Cut(line, " ")
		if !ok || key == "" || !validValue(value) {
			return nil, fmt.Errorf("self-check: %s has a malformed line %q", name, line)
		}
		if _, dup := out[key]; dup {
			return nil, fmt.Errorf("self-check: %s lists %s twice", name, key)
		}
		out[key] = value
	}
	return out, nil
}

func checkUsers(content string, mailboxes map[string]string) error {
	seen := map[string]bool{}
	if content != "" {
		if !strings.HasSuffix(content, "\n") {
			return fmt.Errorf("self-check: %s is not newline-terminated", FileUsers)
		}
		for _, line := range strings.Split(strings.TrimSuffix(content, "\n"), "\n") {
			f := strings.Split(line, ":")
			if len(f) != 8 || !strings.HasPrefix(f[1], "{") || f[0] == "" || f[5] == "" {
				return fmt.Errorf("self-check: %s has a malformed line for %q", FileUsers, f[0])
			}
			if _, ok := mailboxes[f[0]]; !ok {
				return fmt.Errorf("self-check: %s has %s, which postfix/mailboxes does not", FileUsers, f[0])
			}
			seen[f[0]] = true
		}
	}
	for m := range mailboxes {
		if !seen[m] {
			return fmt.Errorf("self-check: %s is in postfix/mailboxes but not %s", m, FileUsers)
		}
	}
	return nil
}
