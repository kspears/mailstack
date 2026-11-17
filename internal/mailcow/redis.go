package mailcow

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"time"
)

const (
	dialTimeout    = 10 * time.Second
	commandTimeout = 30 * time.Second
	maxBulk        = 512 << 20
)

// readOnlyCommands are the only commands a read-only client will send.
var readOnlyCommands = map[string]bool{
	"AUTH": true, "HGETALL": true, "HLEN": true, "SCAN": true, "DUMP": true, "PTTL": true,
}

// Redis is a minimal RESP2 client: one connection, one command at a time.
type Redis struct {
	conn     net.Conn
	r        *bufio.Reader
	readOnly bool
}

// DialRedis connects and authenticates. A read-only client refuses to send
// any command that could change the server.
func DialRedis(addr, password string, readOnly bool) (*Redis, error) {
	conn, err := net.DialTimeout("tcp", addr, dialTimeout)
	if err != nil {
		return nil, fmt.Errorf("connect to redis at %s: %w", addr, err)
	}
	c := &Redis{conn: conn, r: bufio.NewReader(conn), readOnly: readOnly}
	if password != "" {
		if _, err := c.Do("AUTH", password); err != nil {
			conn.Close()
			return nil, fmt.Errorf("authenticate to redis at %s: %w", addr, err)
		}
	}
	return c, nil
}

func (c *Redis) Close() error { return c.conn.Close() }

// Do sends one command and returns its reply as nil, string, int64 or []any.
func (c *Redis) Do(args ...string) (any, error) {
	replies, err := c.Pipeline([][]string{args})
	if err != nil {
		return nil, err
	}
	return replies[0], nil
}

// Pipeline sends every command before it reads any reply, and returns the replies
// in order, each as Do would. A command a read-only client may not send fails the
// whole call before anything is sent. A redis error reply fails the call at that
// command; the connection is not usable afterwards.
func (c *Redis) Pipeline(cmds [][]string) ([]any, error) {
	var b strings.Builder
	for _, args := range cmds {
		if c.readOnly && !readOnlyCommands[strings.ToUpper(args[0])] {
			return nil, fmt.Errorf("refusing to send %s to a read-only redis connection", strings.ToUpper(args[0]))
		}
		fmt.Fprintf(&b, "*%d\r\n", len(args))
		for _, a := range args {
			fmt.Fprintf(&b, "$%d\r\n%s\r\n", len(a), a)
		}
	}
	c.conn.SetDeadline(time.Now().Add(commandTimeout))
	if _, err := io.WriteString(c.conn, b.String()); err != nil {
		return nil, fmt.Errorf("send %s: %w", strings.ToUpper(cmds[0][0]), err)
	}
	replies := make([]any, len(cmds))
	for i, args := range cmds {
		c.conn.SetReadDeadline(time.Now().Add(commandTimeout))
		var err error
		if replies[i], err = readReply(c.r); err != nil {
			return nil, fmt.Errorf("%s: %w", strings.ToUpper(args[0]), err)
		}
	}
	return replies, nil
}

func readReply(r *bufio.Reader) (any, error) {
	line, err := r.ReadString('\n')
	if err != nil {
		return nil, fmt.Errorf("read reply: %w", err)
	}
	line = strings.TrimSuffix(line, "\r\n")
	if line == "" {
		return nil, errors.New("empty reply from redis")
	}
	kind, rest := line[0], line[1:]
	switch kind {
	case '+':
		return rest, nil
	case '-':
		return nil, errors.New("redis: " + rest)
	}
	n, err := strconv.ParseInt(rest, 10, 64)
	if err != nil {
		return nil, fmt.Errorf("malformed reply %q", line)
	}
	switch kind {
	case ':':
		return n, nil
	case '$':
		return readBulk(r, n)
	case '*':
		return readArray(r, n)
	}
	return nil, fmt.Errorf("unexpected reply type %q", kind)
}

func readBulk(r *bufio.Reader, n int64) (any, error) {
	if n < 0 {
		return nil, nil
	}
	if n > maxBulk {
		return nil, fmt.Errorf("bulk reply of %d bytes is too large", n)
	}
	buf := make([]byte, n+2)
	if _, err := io.ReadFull(r, buf); err != nil {
		return nil, fmt.Errorf("read reply: %w", err)
	}
	return string(buf[:n]), nil
}

func readArray(r *bufio.Reader, n int64) (any, error) {
	if n < 0 {
		return nil, nil
	}
	out := make([]any, 0, min(n, 1024))
	for range n {
		v, err := readReply(r)
		if err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, nil
}

// HGetAll returns every field of a hash; a missing key is an empty map.
func (c *Redis) HGetAll(key string) (map[string]string, error) {
	reply, err := c.Do("HGETALL", key)
	if err != nil {
		return nil, err
	}
	items, _ := reply.([]any)
	if len(items)%2 != 0 {
		return nil, fmt.Errorf("HGETALL %s: odd number of elements", key)
	}
	out := make(map[string]string, len(items)/2)
	for i := 0; i < len(items); i += 2 {
		k, kok := items[i].(string)
		v, vok := items[i+1].(string)
		if !kok || !vok {
			return nil, fmt.Errorf("HGETALL %s: unexpected element type", key)
		}
		out[k] = v
	}
	return out, nil
}

func (c *Redis) HLen(key string) (int, error) {
	n, err := c.integer("HLEN", key)
	return int(n), err
}

func (c *Redis) integer(args ...string) (int64, error) {
	reply, err := c.Do(args...)
	if err != nil {
		return 0, err
	}
	n, ok := reply.(int64)
	if !ok {
		return 0, fmt.Errorf("%s: expected an integer reply", args[0])
	}
	return n, nil
}

// Scan returns one page of keys matching pattern and the next cursor; "0" ends the iteration.
func (c *Redis) Scan(cursor, pattern string) (string, []string, error) {
	reply, err := c.Do("SCAN", cursor, "MATCH", pattern, "COUNT", "1000")
	if err != nil {
		return "", nil, err
	}
	parts, _ := reply.([]any)
	if len(parts) != 2 {
		return "", nil, errors.New("SCAN: malformed reply")
	}
	next, _ := parts[0].(string)
	items, _ := parts[1].([]any)
	keys := make([]string, 0, len(items))
	for _, it := range items {
		k, ok := it.(string)
		if !ok {
			return "", nil, errors.New("SCAN: unexpected element type")
		}
		keys = append(keys, k)
	}
	return next, keys, nil
}
