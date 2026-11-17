package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

const (
	learnUsage      = "learn --controller <url> --password-file <path> spam|ham   (one message on stdin)"
	maxLearnBytes   = 32 << 20
	learnTimeout    = 10 * time.Second
	maxLearnErrText = 200
)

// refusals are rspamd answers to a message it will not train on. They are not
// operational failures: re-learning the same message, or a message with too few
// tokens, must not make a mail client's Sieve script report an error.
var refusals = []string{"already learned", "too few tokens", "less than", "not enough", "learn conditions"}

// learn trains rspamd on one message from stdin through its controller. It needs
// no state directory and never opens the store.
func (e *env) learn(args []string) error {
	var controller, passwordFile string
	fs := flag.NewFlagSet("learn", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	fs.StringVar(&controller, "controller", "", "")
	fs.StringVar(&passwordFile, "password-file", "", "")
	pos, err := parseInterspersed(fs, args)
	if err != nil || controller == "" || passwordFile == "" || len(pos) != 1 || (pos[0] != "spam" && pos[0] != "ham") {
		return usageError(learnUsage)
	}
	kind := pos[0]
	pw, err := os.ReadFile(passwordFile)
	if err != nil {
		return fmt.Errorf("read the rspamd controller password file: %w", err)
	}
	msg, err := io.ReadAll(io.LimitReader(e.stdin, maxLearnBytes+1))
	if err != nil {
		return fmt.Errorf("read the message from stdin: %w", err)
	}
	if len(msg) == 0 || len(msg) > maxLearnBytes {
		return fmt.Errorf("expected one message of 1 to %d bytes on stdin", maxLearnBytes)
	}
	req, err := http.NewRequest(http.MethodPost, strings.TrimSuffix(controller, "/")+"/learn"+kind, bytes.NewReader(msg))
	if err != nil {
		return fmt.Errorf("--controller is not a valid URL: %w", err)
	}
	req.Header.Set("Password", strings.TrimSpace(string(pw)))
	req.Header.Set("Content-Type", "message/rfc822")
	resp, err := (&http.Client{Timeout: learnTimeout}).Do(req)
	if err != nil {
		return fmt.Errorf("reach rspamd's controller at %s: %w", controller, err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	if resp.StatusCode == http.StatusOK || resp.StatusCode == http.StatusNoContent || resp.StatusCode == http.StatusAlreadyReported {
		fmt.Fprintf(e.stdout, "ok: learned as %s\n", kind)
		return nil
	}
	reason := controllerError(body)
	if resp.StatusCode >= 400 && resp.StatusCode < 500 && refused(reason) {
		fmt.Fprintf(e.stdout, "ok: rspamd did not learn the message: %s\n", reason)
		return nil
	}
	return fmt.Errorf("rspamd's controller answered %s to learn %s: %s", resp.Status, kind, reason)
}

func controllerError(body []byte) string {
	var v struct{ Error string }
	text := strings.TrimSpace(string(body))
	if json.Unmarshal(body, &v) == nil && v.Error != "" {
		text = v.Error
	}
	if len(text) > maxLearnErrText {
		text = text[:maxLearnErrText]
	}
	return text
}

func refused(reason string) bool {
	r := strings.ToLower(reason)
	for _, s := range refusals {
		if strings.Contains(r, s) {
			return true
		}
	}
	return false
}
