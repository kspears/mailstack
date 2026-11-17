#!/usr/bin/env bash
# Integration test: brings up the reference stack and drives it the way users and the
# internet would. Needs docker with compose v2 and openssl on the host. Run from anywhere:
#   deploy/ci/test.sh
set -euo pipefail

cd "$(dirname "$0")"
export COMPOSE_PROGRESS=quiet

PASSWORD="ci-test-password-$(openssl rand -hex 6)"
KEYS=.keys

cleanup() {
	status=$?
	if [ "$status" -ne 0 ] || [ -n "${CI_SHOW_LOGS:-}" ]; then
		echo "--- container logs ---" >&2
		docker compose --profile tools logs --no-color --tail 200 >&2 || true
	fi
	docker compose --profile tools down -v --remove-orphans >/dev/null 2>&1 || true
	rm -r "$KEYS" || true
	exit "$status"
}
trap cleanup EXIT

step() { printf '\n== %s\n' "$*"; }

mailctl() { docker compose run --rm -T admin "$@"; }
probe() { docker compose run --rm -T --no-deps probe "$@"; }

# Succeeds only if mailctl printed an "ok:" line. Passwords arrive as two stdin lines.
expect_ok() {
	local out
	out=$("$@") || { echo "FAIL: '$*' exited non-zero: $out"; return 1; }
	case "$out" in
		ok:*) echo "$out" ;;
		*) echo "FAIL: '$*' printed: $out"; return 1 ;;
	esac
}

step "build images"
docker compose --profile tools build --quiet

step "generate throwaway TLS, mail-encryption and rspamd controller keys"
mkdir -p "$KEYS/tls" "$KEYS/mail_crypt" "$KEYS/rspamd"
# The controller password is shared by rspamd (config include), dovecot (`mailctl learn`) and the
# probe (which reads /stat). It lives only in this throwaway directory.
CONTROLLER_PASSWORD=$(openssl rand -hex 16)
printf '%s' "$CONTROLLER_PASSWORD" >"$KEYS/rspamd/controller-password"
printf 'password = "%s";\nenable_password = "%s";\n' "$CONTROLLER_PASSWORD" "$CONTROLLER_PASSWORD" >"$KEYS/rspamd/controller.inc"
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -days 2 \
	-subj /CN=mail.example.test -addext subjectAltName=DNS:mail.example.test \
	-keyout "$KEYS/tls/tls.key" -out "$KEYS/tls/tls.crt" 2>/dev/null
# dovecot requires PKCS#8 ("BEGIN PRIVATE KEY"); a bare `ecparam -genkey` emits "EC PRIVATE KEY".
openssl ecparam -name prime256v1 -genkey -noout | openssl pkey -out "$KEYS/mail_crypt/ecprivkey.pem"
openssl pkey -in "$KEYS/mail_crypt/ecprivkey.pem" -pubout -out "$KEYS/mail_crypt/ecpubkey.pem"
# Throwaway keys, and the mail user (uid 5000) must be able to read the private one.
chmod -R a+rX "$KEYS"
chmod a+r "$KEYS"/*/*

step "bootstrap: first generation, written without a watcher (none is running yet)"
expect_ok docker compose run --rm -T -e MAILCTL_WATCHER=off admin domain add example.test

step "start the stack"
docker compose up -d --wait --wait-timeout 120 redis rspamd
docker compose up -d dovecot postfix
probe wait postfix:25 postfix:465 postfix:587 dovecot:993 dovecot:24 dovecot:12345 rspamd:11332

step "mailctl changes go through the real watcher: pending -> status -> current -> reload"
printf '%s\n%s\n' "$PASSWORD" "$PASSWORD" | expect_ok docker compose run --rm -T admin mailbox add alice@example.test --name Alice
expect_ok mailctl alias add info@example.test alice@example.test

step "deliver to the alias from outside, read it back over IMAPS"
subject="ci-$(openssl rand -hex 4)"
probe deliver info@example.test "$subject" "hello from the integration test"
probe fetch alice@example.test "$PASSWORD" "$subject" "hello from the integration test"

step "spam goes to Junk (rspamd add_header -> X-Spam -> dovecot Sieve)"
spam="ci-spam-$(openssl rand -hex 4)"
probe deliver alice@example.test "$spam" "buy things" spam
probe fetch alice@example.test "$PASSWORD" "$spam" "buy things" Junk
probe absent alice@example.test "$PASSWORD" "$spam" INBOX

step "moving mail into Junk trains rspamd as spam, and back out as ham (IMAPSieve -> mailctl learn)"
# Bayes refuses messages with too few tokens, so the body has to be a real paragraph.
train="ci-train-$(openssl rand -hex 4)"
body="The quarterly planning meeting covers the garden fence repairs, the invoice for the new bicycle shed, \
and the schedule for painting the hallway. Please bring the surveyor's drawings, the blue folder with the \
council letters, and a list of questions about the drainage work along the northern boundary of the field."
probe deliver alice@example.test "$train" "$body"
probe fetch alice@example.test "$PASSWORD" "$train" "garden fence repairs"
spam_before=$(probe learned spam)
probe move alice@example.test "$PASSWORD" "$train" INBOX Junk
probe wait-learned spam $((spam_before + 1))
ham_before=$(probe learned ham)
probe move alice@example.test "$PASSWORD" "$train" Junk INBOX
probe wait-learned ham $((ham_before + 1))

step "postfix and dovecot see only the generated files, and postfix writes only watcher/"
# Neither container may read the account store or the DKIM keys, or change what mailctl published.
docker compose exec -T postfix sh -c '
	[ ! -e /data/mailstack/store.db ] && [ ! -e /data/mailstack/dkim ] || { echo "FAIL: postfix sees store.db or dkim"; exit 1; }
	if touch /data/mailstack/generations/probe 2>/dev/null; then echo "FAIL: postfix can write generations"; exit 1; fi
	touch /data/mailstack/watcher/.probe && rm /data/mailstack/watcher/.probe || { echo "FAIL: postfix cannot write watcher"; exit 1; }
	echo "postfix: generations read-only, watcher writable, no store.db"'
docker compose exec -T dovecot sh -c '
	[ ! -e /data/mailstack/store.db ] && [ ! -e /data/mailstack/watcher ] || { echo "FAIL: dovecot sees more than generations"; exit 1; }
	if touch /data/mailstack/generations/probe 2>/dev/null; then echo "FAIL: dovecot can write generations"; exit 1; fi
	echo "dovecot: generations read-only, nothing else"'

step "the watcher is restarted if it dies"
# The bracket keeps this command line from matching its own pattern.
docker compose exec -T postfix sh -c 'for p in /proc/[0-9]*; do case "$(tr "\0" " " <"$p/cmdline")" in *watcher.s[h]*) kill "${p#/proc/}";; esac; done'
expect_ok mailctl alias add ops@example.test alice@example.test

step "port 25 is not an open relay and offers no AUTH"
probe relay-denied

step "unknown recipients are refused during SMTP"
probe unknown-recipient

step "submission: TLS first, own address only"
probe auth-needs-tls alice@example.test "$PASSWORD"
probe submission-ok alice@example.test "$PASSWORD"
probe forged-sender alice@example.test "$PASSWORD"

printf '\nall checks passed\n'
