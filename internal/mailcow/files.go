package mailcow

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

// Items that live in files on disk rather than in mailcow's database.
const (
	itemSieveScripts    = "sieve-scripts"
	itemSharedFolderACL = "shared-folder-acls"
	itemRspamdMaps      = "global-rspamd-maps"
)

// readFiles fills the counts of the three file-backed stop items. An item whose
// directory is not set or cannot be read goes in d.Unchecked with the reason
// instead: a count of zero must only ever mean "looked, found nothing".
func (l Live) readFiles(d *Data) {
	d.Unchecked = map[string]string{}
	check := func(item, dir, setting string, count func(string) (int, error)) {
		if dir == "" {
			d.Unchecked[item] = setting + " is not set"
			return
		}
		n, err := count(dir)
		if err != nil {
			d.Unchecked[item] = err.Error()
			return
		}
		d.Counts[item] = n
	}
	check(itemSieveScripts, l.MailRoot, "MAILCOW_VMAIL_ROOT (or MAILCTL_MAIL_ROOT)", CountSieveScripts)
	check(itemSharedFolderACL, l.MailRoot, "MAILCOW_VMAIL_ROOT (or MAILCTL_MAIL_ROOT)", CountFolderACLs)
	check(itemRspamdMaps, l.RspamdCustomDir, "MAILCOW_RSPAMD_CUSTOM_DIR", CountRspamdMapLines)
}

// mailboxHomes lists <root>/<domain>/<user> directories. The top-level "sieve"
// directory holds mailcow's global scripts, not a domain.
func mailboxHomes(root string) ([]string, error) {
	domains, err := os.ReadDir(root)
	if err != nil {
		return nil, err
	}
	var homes []string
	for _, dom := range domains {
		if !dom.IsDir() || dom.Name() == "sieve" {
			continue
		}
		users, err := os.ReadDir(filepath.Join(root, dom.Name()))
		if err != nil {
			return nil, err
		}
		for _, u := range users {
			if u.IsDir() {
				homes = append(homes, filepath.Join(root, dom.Name(), u.Name()))
			}
		}
	}
	return homes, nil
}

// CountSieveScripts counts user Sieve scripts under a mail root: files matching
// <root>/sieve/*.sieve except mailcow's two global scripts, plus, in each mailbox
// home, every *.sieve file and a non-empty sieve/ directory.
func CountSieveScripts(root string) (int, error) {
	homes, err := mailboxHomes(root)
	if err != nil {
		return 0, err
	}
	n := 0
	global, err := os.ReadDir(filepath.Join(root, "sieve"))
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return 0, err
	}
	for _, e := range global {
		if !e.IsDir() && strings.HasSuffix(e.Name(), ".sieve") &&
			e.Name() != "global_sieve_before.sieve" && e.Name() != "global_sieve_after.sieve" {
			n++
		}
	}
	for _, home := range homes {
		entries, err := os.ReadDir(home)
		if err != nil {
			return 0, err
		}
		for _, e := range entries {
			switch {
			case e.IsDir() && e.Name() == "sieve":
				inner, err := os.ReadDir(filepath.Join(home, "sieve"))
				if err != nil {
					return 0, err
				}
				if len(inner) > 0 {
					n++
				}
			case !e.IsDir() && strings.HasSuffix(e.Name(), ".sieve"):
				n++
			}
		}
	}
	return n, nil
}

// CountFolderACLs counts non-empty dovecot-acl files in any mailbox's Maildir and
// its folder directories, plus a non-empty <root>/shared-mailboxes.db. It walks
// directories only and never descends into cur, new or tmp.
func CountFolderACLs(root string) (int, error) {
	homes, err := mailboxHomes(root)
	if err != nil {
		return 0, err
	}
	n := 0
	if st, err := os.Stat(filepath.Join(root, "shared-mailboxes.db")); err == nil && st.Size() > 0 {
		n++
	} else if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return 0, err
	}
	for _, home := range homes {
		maildir := filepath.Join(home, "Maildir")
		err := filepath.WalkDir(maildir, func(path string, e fs.DirEntry, err error) error {
			if err != nil {
				if path == maildir && errors.Is(err, fs.ErrNotExist) {
					return fs.SkipAll
				}
				return err
			}
			if !e.IsDir() {
				return nil
			}
			if name := e.Name(); path != maildir && (name == "cur" || name == "new" || name == "tmp") {
				return fs.SkipDir
			}
			if st, err := os.Stat(filepath.Join(path, "dovecot-acl")); err == nil && st.Size() > 0 {
				n++
			}
			return nil
		})
		if err != nil {
			return 0, err
		}
	}
	return n, nil
}

// CountRspamdMapLines counts non-blank, non-comment lines across the *.map files
// directly inside dir.
func CountRspamdMapLines(dir string) (int, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return 0, err
	}
	n := 0
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".map") {
			continue
		}
		b, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			return 0, fmt.Errorf("read %s: %w", e.Name(), err)
		}
		for _, line := range strings.Split(string(b), "\n") {
			if line = strings.TrimSpace(line); line != "" && !strings.HasPrefix(line, "#") {
				n++
			}
		}
	}
	return n, nil
}
