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
# Pull the images that are not built here while the build runs.
docker compose --profile tools pull --ignore-buildable --quiet &
docker compose --profile tools build --quiet
wait

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
docker compose up -d --wait --wait-timeout 120 redis unbound rspamd
docker compose up -d dovecot postfix
probe wait postfix:25 postfix:465 postfix:587 dovecot:993 dovecot:24 dovecot:12345 rspamd:11332

step "the postfix watcher keeps its heartbeat fresh"
beat() { docker compose exec -T postfix stat -c %Y /data/mailstack/watcher/heartbeat; }
first=$(beat) || { echo "FAIL: no watcher heartbeat"; exit 1; }
sleep 3
[ "$(beat)" -gt "$first" ] || { echo "FAIL: the watcher heartbeat did not move in 3 seconds"; exit 1; }
echo "heartbeat: moving"

step "mailctl changes go through the real watcher: pending -> status -> current -> reload"
printf '%s\n%s\n' "$PASSWORD" "$PASSWORD" | expect_ok mailctl mailbox add alice@example.test --name Alice
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
# The status page reads delivery times from this folder, so pin its name on disk.
docker compose exec -T dovecot sh -c 'find /var/vmail/example.test/alice/Maildir/.Junk/new /var/vmail/example.test/alice/Maildir/.Junk/cur -type f 2>/dev/null; true' | grep -q . ||
	{ echo "FAIL: spam is not under Maildir/.Junk"; exit 1; }

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
# postfix and rspamd resolve through the stack's own unbound: the name exists only there.
for svc in postfix rspamd; do
	got=$(docker compose exec -T "$svc" getent ahostsv4 probe.unbound.test | awk 'NR==1 {print $1}')
	[ "$got" = 192.0.2.53 ] || { echo "FAIL: $svc does not resolve through unbound (got '$got')"; exit 1; }
	echo "$svc: resolves through unbound"
done
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

step "the admin UI and the rspamd UI, through the proxy"
docker compose up -d ui proxy
probe wait proxy:443
link=$(mailctl admin add webadmin@example.test | tail -n 1)
case "$link" in
	https://admin.example.test/enrol\?t=*) ;;
	*) echo "FAIL: mailctl admin add printed no enrolment link"; exit 1 ;;
esac
docker compose run --rm -T --no-deps --entrypoint python probe -I /webprobe.py "${link#*t=}"
# The failed sign-in claimed to come from 203.0.113.99. The proxy must have replaced that
# with the address it saw the connection come from, on the edge network.
ui_log=$(docker compose logs --no-color ui)
case "$ui_log" in *203.0.113.99*) echo "FAIL: the UI believed a visitor-supplied address"; exit 1 ;; esac
case "$ui_log" in
	*"sign-in failed from=10.254.77."*) echo "ok: a failed sign-in is logged with the address the proxy saw" ;;
	*) echo "FAIL: no failed sign-in logged with the visitor's address"; exit 1 ;;
esac
case "$ui_log" in *"${link#*t=}"*) echo "FAIL: the UI logged the enrolment token"; exit 1 ;; esac

printf '\nall checks passed\n'
