package mailcow

import (
	"fmt"
	"strconv"
)

// DefaultBayesPatterns are the key patterns rspamd's statistics live under.
var DefaultBayesPatterns = []string{"BAYES_*", "RS*", "learned_ids*"}

// PatternCount is how many keys one pattern matched.
type PatternCount struct {
	Pattern string
	Keys    int
}

// CopyKeys copies every key matching the patterns from src to dst with its
// TTL. With a nil dst it only counts what SCAN returns, without reading any key.
// Nothing is deleted anywhere. A key that matches several patterns is copied
// once and counted for the first.
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
			var fresh []string
			for _, key := range keys {
				if !seen[key] {
					seen[key] = true
					fresh = append(fresh, key)
				}
			}
			n, err := copyPage(src, dst, fresh)
			if err != nil {
				return out, fmt.Errorf("copy keys matching %s: %w", pattern, err)
			}
			count.Keys += n
			if cursor = next; cursor == "0" {
				break
			}
		}
		out = append(out, count)
	}
	return out, nil
}

// copyPage copies one SCAN page in two round trips: DUMP and PTTL for every key
// from src, then RESTORE for every key that still existed to dst. It returns how
// many keys were copied; with a nil dst, how many there are.
func copyPage(src, dst *Redis, keys []string) (int, error) {
	if dst == nil || len(keys) == 0 {
		return len(keys), nil
	}
	reads := make([][]string, 0, 2*len(keys))
	for _, key := range keys {
		reads = append(reads, []string{"DUMP", key}, []string{"PTTL", key})
	}
	replies, err := src.Pipeline(reads)
	if err != nil {
		return 0, err
	}
	var writes [][]string
	for i, key := range keys {
		payload, ok := replies[2*i].(string)
		if !ok {
			continue // deleted or expired since SCAN
		}
		ttl, _ := replies[2*i+1].(int64)
		if ttl == -2 {
			continue
		}
		writes = append(writes, []string{"RESTORE", key, strconv.FormatInt(max(ttl, 0), 10), payload, "REPLACE"})
	}
	if len(writes) == 0 {
		return 0, nil
	}
	if _, err := dst.Pipeline(writes); err != nil {
		return 0, err
	}
	return len(writes), nil
}
