package mailcow

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	_ "github.com/go-sql-driver/mysql"
)

// Every statement mailcow's MySQL ever sees from this package is one of these
// SELECTs, run inside a read-only transaction.
const (
	queryDomains = `SELECT domain, active, backupmx, relay_all_recipients, relay_unknown_only,
		CAST(COALESCE(relayhost, 0) AS CHAR) FROM domain ORDER BY domain`
	queryMailboxes = `SELECT username, COALESCE(name, ''), password, active, COALESCE(quota, 0),
		COALESCE(attributes, '') FROM mailbox ORDER BY username`
	queryAliases     = `SELECT address, goto, active FROM alias ORDER BY address`
	querySenderACLs  = `SELECT logged_in_as, send_as, external FROM sender_acl ORDER BY id`
	queryRelayhosts  = `SELECT CAST(id AS CHAR), hostname FROM relayhosts ORDER BY id`
	queryTableExists = `SELECT COUNT(*) FROM information_schema.tables
		WHERE table_schema = DATABASE() AND table_name = ?`
)

// countQueries fill Data.Counts. A table missing from the schema counts as zero.
var countQueries = []struct{ item, table, query string }{
	{"alias-domains", "alias_domain", `SELECT COUNT(*) FROM alias_domain`},
	{"bcc-maps", "bcc_maps", `SELECT COUNT(*) FROM bcc_maps`},
	{"recipient-maps", "recipient_maps", `SELECT COUNT(*) FROM recipient_maps`},
	{"transport-maps", "transports", `SELECT COUNT(*) FROM transports`},
	{"temporary-aliases", "spamalias", `SELECT COUNT(*) FROM spamalias`},
	{"sync-jobs", "imapsync", `SELECT COUNT(*) FROM imapsync`},
	{"forwarding-hosts", "forwarding_hosts", `SELECT COUNT(*) FROM forwarding_hosts`},
	{"domain-footers", "domain_wide_footer", `SELECT COUNT(*) FROM domain_wide_footer`},
	{"sieve-filters", "sieve_filters", `SELECT COUNT(*) FROM sieve_filters`},
	{"spam-settings", "filterconf", `SELECT COUNT(*) FROM filterconf`},
	{"app-passwords", "app_passwd", `SELECT COUNT(*) FROM app_passwd WHERE active = 1`},
	{"tfa", "tfa", `SELECT COUNT(*) FROM tfa WHERE username IN (SELECT username FROM mailbox)`},
}

const (
	redisDKIMKeys      = "DKIM_PRIV_KEYS"
	redisDKIMSelectors = "DKIM_SELECTORS"
	redisRateLimits    = "RL_VALUE"
)

// Live reads a running mailcow: MySQL for accounts, Redis for DKIM keys and rate limits.
type Live struct {
	DB    *sql.DB
	Redis *Redis
}

func (l Live) Read(ctx context.Context) (Data, error) {
	var d Data
	tx, err := l.DB.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return d, fmt.Errorf("start read-only transaction on mailcow's MySQL: %w", err)
	}
	defer tx.Rollback()
	if err := readSQL(ctx, tx, &d); err != nil {
		return d, err
	}
	if err := l.readRedis(&d); err != nil {
		return d, err
	}
	return d, nil
}

func readSQL(ctx context.Context, tx *sql.Tx, d *Data) error {
	steps := []struct {
		what  string
		query string
		each  func(*sql.Rows) error
	}{
		{"domain", queryDomains, func(r *sql.Rows) error {
			var x Domain
			err := r.Scan(&x.Name, &x.Active, &x.BackupMX, &x.RelayAll, &x.RelayUnknown, &x.RelayhostID)
			d.Domains = append(d.Domains, x)
			return err
		}},
		{"mailbox", queryMailboxes, func(r *sql.Rows) error {
			var x Mailbox
			err := r.Scan(&x.Address, &x.Name, &x.Hash, &x.Active, &x.Quota, &x.Attributes)
			d.Mailboxes = append(d.Mailboxes, x)
			return err
		}},
		{"alias", queryAliases, func(r *sql.Rows) error {
			var x Alias
			err := r.Scan(&x.Address, &x.Goto, &x.Active)
			d.Aliases = append(d.Aliases, x)
			return err
		}},
		{"sender_acl", querySenderACLs, func(r *sql.Rows) error {
			var x SenderACL
			err := r.Scan(&x.LoggedInAs, &x.SendAs, &x.External)
			d.SenderACLs = append(d.SenderACLs, x)
			return err
		}},
		{"relayhosts", queryRelayhosts, func(r *sql.Rows) error {
			var x Relayhost
			err := r.Scan(&x.ID, &x.Hostname)
			d.Relayhosts = append(d.Relayhosts, x)
			return err
		}},
	}
	for _, s := range steps {
		if err := each(ctx, tx, s.query, s.each); err != nil {
			return fmt.Errorf("read mailcow %s table: %w", s.what, err)
		}
	}
	d.Counts = map[string]int{}
	for _, c := range countQueries {
		n, err := countRows(ctx, tx, c.table, c.query)
		if err != nil {
			return fmt.Errorf("count mailcow %s rows: %w", c.table, err)
		}
		d.Counts[c.item] = n
	}
	return nil
}

func each(ctx context.Context, tx *sql.Tx, query string, fn func(*sql.Rows) error) error {
	rows, err := tx.QueryContext(ctx, query)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		if err := fn(rows); err != nil {
			return err
		}
	}
	return rows.Err()
}

func countRows(ctx context.Context, tx *sql.Tx, table, query string) (int, error) {
	var exists int
	if err := tx.QueryRowContext(ctx, queryTableExists, table).Scan(&exists); err != nil {
		return 0, err
	}
	if exists == 0 {
		return 0, nil
	}
	var n int
	err := tx.QueryRowContext(ctx, query).Scan(&n)
	return n, err
}

func (l Live) readRedis(d *Data) error {
	if l.Redis == nil {
		return errors.New("no connection to mailcow's redis")
	}
	var err error
	if d.DKIMKeys, err = l.Redis.HGetAll(redisDKIMKeys); err != nil {
		return fmt.Errorf("read %s from mailcow's redis: %w", redisDKIMKeys, err)
	}
	if d.DKIMSelectors, err = l.Redis.HGetAll(redisDKIMSelectors); err != nil {
		return fmt.Errorf("read %s from mailcow's redis: %w", redisDKIMSelectors, err)
	}
	if d.Counts["rate-limits"], err = l.Redis.HLen(redisRateLimits); err != nil {
		return fmt.Errorf("read %s from mailcow's redis: %w", redisRateLimits, err)
	}
	return nil
}
