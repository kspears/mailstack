package mailcow

import "fmt"

// DefaultBayesPatterns are the key patterns rspamd's statistics live under.
var DefaultBayesPatterns = []string{"BAYES_*", "RS*", "learned_ids*"}

// PatternCount is how many keys one pattern matched.
type PatternCount struct {
	Pattern string
	Keys    int
}

// CopyKeys copies every key matching the patterns from src to dst with its
// TTL. With a nil dst it only counts. Nothing is deleted anywhere. A key that
// matches several patterns is copied once and counted for the first.
func CopyKeys(src, dst *Redis, patterns []string) ([]PatternCount, error) {
	seen := map[string]bool{}
	var out []PatternCount
	for _, pattern := range patterns {
		count := PatternCount{Pattern: pattern}
		cursor := "0"
		for {
			next, keys, err := src.Scan(cursor, pattern)
			if err != nil {
				return out, err
			}
			for _, key := range keys {
				if seen[key] {
					continue
				}
				seen[key] = true
				copied, err := copyKey(src, dst, key)
				if err != nil {
					return out, fmt.Errorf("copy key %s: %w", key, err)
				}
				if copied {
					count.Keys++
				}
			}
			if cursor = next; cursor == "0" {
				break
			}
		}
		out = append(out, count)
	}
	return out, nil
}

func copyKey(src, dst *Redis, key string) (bool, error) {
	payload, ok, err := src.Dump(key)
	if err != nil || !ok {
		return false, err
	}
	if dst == nil {
		return true, nil
	}
	ttl, err := src.PTTL(key)
	if err != nil {
		return false, err
	}
	return true, dst.Restore(key, ttl, payload)
}
