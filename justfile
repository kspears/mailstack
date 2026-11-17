set positional-arguments

[private]
default:
    @just --list

# Download Go module dependencies
setup:
    go mod download

# Run the admin UI locally against a scratch state directory
dev *args:
    go run ./cmd/mailctl serve "$@"

# Full CI gate: formatting, vet, tests, build
check: lint test build

# Run unit tests
test *args:
    go test ./... "$@"

# Fail on unformatted code, then vet
lint:
    @test -z "$(gofmt -l .)" || { gofmt -l .; echo "run: just fmt"; exit 1; }
    go vet ./...

# Format all Go code
fmt:
    gofmt -w .

# Build mailctl into bin/
build:
    CGO_ENABLED=0 go build -o bin/mailctl ./cmd/mailctl
