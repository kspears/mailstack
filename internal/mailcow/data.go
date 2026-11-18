// Package mailcow reads a running mailcow-dockerized install and plans the
// one-time import of its accounts into a mailstack store. Reading, planning and
// writing are separate: Plan does no I/O.
package mailcow

// Data is what was read from mailcow, as plain values.
type Data struct {
	Domains    []Domain
	Mailboxes  []Mailbox
	Aliases    []Alias
	SenderACLs []SenderACL
	Relayhosts []Relayhost

	// Counts holds the row count of each stop item that is a plain table count,
	// keyed by item name. A table that does not exist counts as zero.
	Counts map[string]int

	// Unchecked maps a stop item that could not be counted (its directory is not
	// set or not readable) to the reason. It is a stop unless acknowledged.
	Unchecked map[string]string

	// DKIMSelectors maps a domain to its selector; DKIMKeys maps
	// "<selector>.<domain>" to a PEM private key.
	DKIMSelectors map[string]string
	DKIMKeys      map[string]string
}

type Domain struct {
	Name         string
	Active       bool
	BackupMX     bool
	RelayAll     bool
	RelayUnknown bool
	RelayhostID  string
}

type Mailbox struct {
	Address string
	Name    string
	Hash    string
	// Active is mailcow's flag: 0 disabled, 1 active, 2 receive-only.
	Active int
	Quota  int64
	// Attributes is the raw JSON attributes column.
	Attributes string
}

type Alias struct {
	Address string
	Goto    string
	Active  bool
}

type SenderACL struct {
	LoggedInAs string
	SendAs     string
	External   bool
}

type Relayhost struct {
	ID       string
	Hostname string
	Active   bool
}
