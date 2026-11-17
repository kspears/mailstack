package mailcow

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"path"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
)

type fakeRedis struct {
	addr     string
	password string

	mu       sync.Mutex
	hashes   map[string]map[string]string
	keys     map[string]string
	ttl      map[string]int64
	received [][]string
}

func startFake(t *testing.T, password string) *fakeRedis {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	f := &fakeRedis{addr: l.Addr().String(), password: password,
		hashes: map[string]map[string]string{}, keys: map[string]string{}, ttl: map[string]int64{}}
	t.Cleanup(func() { l.Close() })
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go f.serve(c)
		}
	}()
	return f
}

func (f *fakeRedis) commands() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []string
	for _, c := range f.received {
		out = append(out, strings.ToUpper(c[0]))
	}
	return out
}

func readCommand(r *bufio.Reader) ([]string, error) {
	line, err := r.ReadString('\n')
	if err != nil {
		return nil, err
	}
	n, _ := strconv.Atoi(strings.TrimSpace(line)[1:])
	args := make([]string, n)
	for i := range args {
		hdr, err := r.ReadString('\n')
		if err != nil {
			return nil, err
		}
		size, _ := strconv.Atoi(strings.TrimSpace(hdr)[1:])
		buf := make([]byte, size+2)
		if _, err := io.ReadFull(r, buf); err != nil {
			return nil, err
		}
		args[i] = string(buf[:size])
	}
	return args, nil
}

func bulk(s string) string { return fmt.Sprintf("$%d\r\n%s\r\n", len(s), s) }

func (f *fakeRedis) serve(c net.Conn) {
	defer c.Close()
	r := bufio.NewReader(c)
	authed := f.password == ""
	for {
		args, err := readCommand(r)
		if err != nil {
			return
		}
		f.mu.Lock()
		f.received = append(f.received, args)
		reply := f.handle(args, &authed)
		f.mu.Unlock()
		io.WriteString(c, reply)
	}
}

func (f *fakeRedis) handle(args []string, authed *bool) string {
	cmd := strings.ToUpper(args[0])
	if cmd == "AUTH" {
		if args[1] != f.password {
			return "-WRONGPASS invalid password\r\n"
		}
		*authed = true
		return "+OK\r\n"
	}
	if !*authed {
		return "-NOAUTH Authentication required.\r\n"
	}
	switch cmd {
	case "HGETALL":
		h := f.hashes[args[1]]
		names := make([]string, 0, len(h))
		for k := range h {
			names = append(names, k)
		}
		sort.Strings(names)
		out := fmt.Sprintf("*%d\r\n", 2*len(h))
		for _, k := range names {
			out += bulk(k) + bulk(h[k])
		}
		return out
	case "HLEN":
		return fmt.Sprintf(":%d\r\n", len(f.hashes[args[1]]))
	case "SCAN":
		return f.scan(args)
	case "DUMP":
		v, ok := f.keys[args[1]]
		if !ok {
			return "$-1\r\n"
		}
		return bulk("\x00\r\n" + v)
	case "PTTL":
		if _, ok := f.keys[args[1]]; !ok {
			return ":-2\r\n"
		}
		ttl, ok := f.ttl[args[1]]
		if !ok {
			return ":-1\r\n"
		}
		return fmt.Sprintf(":%d\r\n", ttl)
	case "RESTORE":
		ttl, _ := strconv.ParseInt(args[2], 10, 64)
		f.keys[args[1]] = strings.TrimPrefix(args[3], "\x00\r\n")
		if ttl > 0 {
			f.ttl[args[1]] = ttl
		}
		return "+OK\r\n"
	}
	return "-ERR unknown command\r\n"
}

// scan pages two keys at a time so the client's cursor loop is exercised.
func (f *fakeRedis) scan(args []string) string {
	var all []string
	for k := range f.keys {
		if ok, _ := path.Match(args[3], k); ok {
			all = append(all, k)
		}
	}
	sort.Strings(all)
	start, _ := strconv.Atoi(args[1])
	end := min(start+2, len(all))
	next := "0"
	if end < len(all) {
		next = strconv.Itoa(end)
	}
	out := "*2\r\n" + bulk(next) + fmt.Sprintf("*%d\r\n", end-start)
	for _, k := range all[start:end] {
		out += bulk(k)
	}
	return out
}

func dial(t *testing.T, f *fakeRedis, password string, readOnly bool) *Redis {
	t.Helper()
	c, err := DialRedis(f.addr, password, readOnly)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	return c
}

func TestRedisAuthAndHashes(t *testing.T) {
	f := startFake(t, "s3cret")
	f.hashes["DKIM_PRIV_KEYS"] = map[string]string{"dkim.example.test": "-----BEGIN-----\r\nline\r\n"}
	if _, err := DialRedis(f.addr, "wrong", true); err == nil || strings.Contains(err.Error(), "wrong") {
		t.Errorf("bad password: %v", err)
	}
	c := dial(t, f, "s3cret", true)
	got, err := c.HGetAll("DKIM_PRIV_KEYS")
	if err != nil || !reflect.DeepEqual(got, f.hashes["DKIM_PRIV_KEYS"]) {
		t.Errorf("HGETALL = %v, %v", got, err)
	}
	if got, err := c.HGetAll("missing"); err != nil || len(got) != 0 {
		t.Errorf("missing hash = %v, %v", got, err)
	}
	if n, err := c.HLen("DKIM_PRIV_KEYS"); err != nil || n != 1 {
		t.Errorf("HLEN = %d, %v", n, err)
	}
}

func TestReadOnlyClientRefusesWrites(t *testing.T) {
	f := startFake(t, "")
	c := dial(t, f, "", true)
	for _, cmd := range []string{"SET", "DEL", "RESTORE", "FLUSHALL", "EVAL"} {
		if _, err := c.Do(cmd, "k", "v"); err == nil || !strings.Contains(err.Error(), "read-only") {
			t.Errorf("%s: %v", cmd, err)
		}
	}
	if got := f.commands(); len(got) != 0 {
		t.Errorf("server saw %v", got)
	}
}

func TestCopyKeys(t *testing.T) {
	src, dstSrv := startFake(t, ""), startFake(t, "pw")
	for i := range 5 {
		src.keys[fmt.Sprintf("BAYES_SPAM%d", i)] = fmt.Sprintf("v%d\r\n\x00", i)
	}
	src.keys["RS_x"] = "rs"
	src.keys["learned_ids_1"] = "ids"
	src.keys["unrelated"] = "no"
	src.ttl["RS_x"] = 5000
	s, d := dial(t, src, "", true), dial(t, dstSrv, "pw", false)

	counts, err := CopyKeys(s, d, DefaultBayesPatterns)
	if err != nil {
		t.Fatal(err)
	}
	want := []PatternCount{{"BAYES_*", 5}, {"RS*", 1}, {"learned_ids*", 1}}
	if !reflect.DeepEqual(counts, want) {
		t.Errorf("counts = %v, want %v", counts, want)
	}
	if len(dstSrv.keys) != 7 || dstSrv.keys["BAYES_SPAM3"] != "v3\r\n\x00" || dstSrv.keys["unrelated"] != "" {
		t.Errorf("destination keys: %v", dstSrv.keys)
	}
	if dstSrv.ttl["RS_x"] != 5000 || dstSrv.ttl["BAYES_SPAM0"] != 0 {
		t.Errorf("ttls: %v", dstSrv.ttl)
	}
	for _, cmd := range src.commands() {
		if !readOnlyCommands[cmd] {
			t.Errorf("source received %s", cmd)
		}
	}
	if len(src.keys) != 8 {
		t.Error("source keys changed")
	}
}

func TestCopyKeysCountOnly(t *testing.T) {
	src := startFake(t, "")
	src.keys["BAYES_A"] = "a"
	src.keys["RS1"] = "b"
	counts, err := CopyKeys(dial(t, src, "", true), nil, []string{"BAYES_*", "*"})
	if err != nil {
		t.Fatal(err)
	}
	if want := []PatternCount{{"BAYES_*", 1}, {"*", 1}}; !reflect.DeepEqual(counts, want) {
		t.Errorf("counts = %v, want %v", counts, want)
	}
}
