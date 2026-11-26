set positional-arguments

[private]
default:
    @just --list

# Download Go module dependencies
setup:
    go mod download

# Local development keeps its state in .dev/ unless MAILCTL_STATE says otherwise.
dev_env := "MAILCTL_DEV=1 MAILCTL_ADMIN_HOST=localhost:8080 MAILCTL_LISTEN=127.0.0.1:8080 MAILCTL_WATCHER=off MAILCTL_DOVECOT_UID=" + `id -u` + \
    " MAILCTL_STATE=" + env("MAILCTL_STATE", justfile_directory() / ".dev/state") + \
    " MAILCTL_MAIL_ROOT=" + env("MAILCTL_MAIL_ROOT", justfile_directory() / ".dev/mail") + \
    " MAILCTL_INDEX_ROOT=" + env("MAILCTL_INDEX_ROOT", justfile_directory() / ".dev/index")

# Run the admin UI on http://localhost:8080; make an admin first with `just dev-ctl admin add <address>`
dev *args:
    {{dev_env}} go run ./cmd/mailctl serve "$@"

# Run any mailctl command against the same local state as `just dev`
dev-ctl *args:
    {{dev_env}} go run ./cmd/mailctl "$@"

# Full CI gate: formatting, vet, tests, build
check: lint test build

# Run unit tests
test *args:
    go test ./... "$@"

# Fail on unformatted code, then vet
lint:
    @test -z "$(gofmt -l .)" || { gofmt -l .; echo "run: just fmt"; exit 1; }
    go vet ./...

# Report known vulnerabilities in the Go code that is actually reached (scheduled in CI)
vuln:
    go run golang.org/x/vuln/cmd/govulncheck@v1.10.0 ./...

# Format all Go code
fmt:
    gofmt -w .

# Build mailctl into bin/
build:
    CGO_ENABLED=0 go build -o bin/mailctl ./cmd/mailctl
