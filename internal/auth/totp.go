package auth

import (
	"crypto/hmac"
	"crypto/sha1"
	"crypto/subtle"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"net/url"
	"strings"
	"time"
)

// Time-based one-time passwords, RFC 6238 with the parameters every
// authenticator app assumes: HMAC-SHA1, six digits, 30-second steps.
const totpPeriod = 30

var secretEncoding = base32.StdEncoding.WithPadding(base32.NoPadding)

func totpStep(t time.Time) int64 { return t.Unix() / totpPeriod }

func totpCode(secret []byte, step int64) string {
	var counter [8]byte
	binary.BigEndian.PutUint64(counter[:], uint64(step))
	m := hmac.New(sha1.New, secret)
	m.Write(counter[:])
	sum := m.Sum(nil)
	offset := sum[len(sum)-1] & 0x0f
	value := binary.BigEndian.Uint32(sum[offset:offset+4]) & 0x7fffffff
	return fmt.Sprintf("%06d", value%1_000_000)
}

// totpMatch returns the step whose code equals the one typed, allowing one
// step either side of now for clock drift. Every candidate is compared, so the
// time taken does not say which one matched.
func totpMatch(secret []byte, typed string, now time.Time) (step int64, ok bool) {
	typed = strings.Join(strings.Fields(typed), "")
	if len(typed) != 6 || len(secret) == 0 {
		return 0, false
	}
	current := totpStep(now)
	for _, candidate := range []int64{current - 1, current, current + 1} {
		if subtle.ConstantTimeCompare([]byte(totpCode(secret, candidate)), []byte(typed)) == 1 {
			step, ok = candidate, true
		}
	}
	return step, ok
}

// totpURI is what the enrolment QR code encodes.
func totpURI(issuer, account string, secret []byte) string {
	q := url.Values{"secret": {secretEncoding.EncodeToString(secret)}, "issuer": {issuer}}
	return "otpauth://totp/" + url.PathEscape(issuer+":"+account) + "?" + q.Encode()
}

// CodeAt returns the code an authenticator holding the base32 secret shows at
// a given time. The server never needs it; tests and the CI stack do.
func CodeAt(secret string, at time.Time) (string, error) {
	raw, err := secretEncoding.DecodeString(strings.ToUpper(strings.TrimSpace(secret)))
	if err != nil {
		return "", fmt.Errorf("authenticator key is not base32: %w", err)
	}
	return totpCode(raw, totpStep(at)), nil
}
