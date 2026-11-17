#!/bin/sh
# Generation watcher. mailctl renders a new generation directory and points
# generations/pending at it; this script checks it with postfix's own tools and reports the
# verdict in watcher/status (a sibling of generations/, so this container can mount
# generations read-only and write only the one directory it owns). When generations/current
# moves it reloads postfix.
#
# Level-triggered on purpose: every pass compares what the symlinks say now with what was last
# handled, so a missed tick, a restart or a slow start loses nothing. It never moves `current`
# or `pending`; mailctl owns both.
#
# No `set -e`: one failed pass must not end the loop.

STATE=${MAILCTL_STATE:-/data/mailstack}
CONF=${POSTFIX_CONFIG_DIR:-/etc/postfix}
INTERVAL=${WATCHER_INTERVAL:-1}

GENS=$STATE/generations
WATCHER=$STATE/watcher
STATUS=$WATCHER/status

# Every file a complete generation must contain, and which of them are postfix lookup tables.
MAPS="postfix/domains postfix/mailboxes postfix/aliases postfix/sender_login"
FILES="dovecot/users $MAPS"

log() { printf 'watcher: %s\n' "$*"; }

# Relative symlink target reduced to the generation id.
gen_id() {
	t=${1%/}
	printf '%s' "${t##*/}"
}

# Write watcher/status atomically. mailctl polls it, so a torn write must not be visible.
write_status() {
	tmp=$WATCHER/.status.$$
	printf '%s\n' "$1" >"$tmp" && mv -f "$tmp" "$STATUS" && return 0
	rm -f "$tmp"
	log "cannot write $STATUS"
	return 1
}

# Print a one-line reason and return 1 if generation $1 is not usable by postfix.
validate() {
	id=$1
	dir=$GENS/$id

	[ -d "$dir" ] || { echo "generation $id does not exist"; return 1; }

	for rel in $FILES; do
		[ -f "$dir/$rel" ] && [ -r "$dir/$rel" ] || { echo "missing or unreadable $rel"; return 1; }
	done

	# postmap prints parse problems (missing value, bad continuation) as warnings and still
	# exits 0, so any stderr output is the failure signal. The probe key is irrelevant.
	for rel in $MAPS; do
		err=$(postmap -q "__watcher_probe__" "texthash:$dir/$rel" 2>&1 >/dev/null)
		[ -z "$err" ] || { echo "$rel: $err"; return 1; }
	done

	# Check the real config with map paths pointed at this generation, in a scratch copy so the
	# live config is never touched.
	tmp=$(mktemp -d) || { echo "cannot create scratch directory"; return 1; }
	cp -a "$CONF/." "$tmp/" || { rm -r "$tmp"; echo "cannot copy $CONF"; return 1; }
	for f in main.cf master.cf; do
		[ -f "$tmp/$f" ] && sed "s#generations/current/#generations/$id/#g" "$CONF/$f" >"$tmp/$f"
	done
	out=$(postfix -c "$tmp" check 2>&1)
	rc=$?
	rm -r "$tmp"
	[ $rc -eq 0 ] || { echo "postfix check: $out"; return 1; }
	return 0
}

check_pending() {
	if [ ! -L "$GENS/pending" ]; then
		# Forget it, so mailctl pending the same id again later is checked again.
		last_pending=
		return
	fi
	target=$(readlink "$GENS/pending") || return
	[ "$target" != "$last_pending" ] || return

	id=$(gen_id "$target")
	if reason=$(validate "$id"); then
		verdict="$id ok"
	else
		# One line, bounded: status is a single-line protocol.
		verdict="$id error $(printf '%s' "$reason" | tr '\n\r\t' '   ' | cut -c1-300)"
	fi
	write_status "$verdict" || return
	last_pending=$target
	log "checked pending: $verdict"
}

check_current() {
	[ -L "$GENS/current" ] || return
	target=$(readlink "$GENS/current") || return
	[ "$target" != "$last_reload" ] || return

	# Not running yet: postfix will read `current` itself when it starts. Do not record the
	# target, so the first pass after startup reloads once, which is harmless.
	postfix status >/dev/null 2>&1 || return

	if out=$(postfix reload 2>&1); then
		log "reloaded postfix for current=$(gen_id "$target")"
	else
		log "reload failed for current=$(gen_id "$target"): $(printf '%s' "$out" | tr '\n' ' ')"
	fi
	# Recorded even on failure: retrying every second would only flood the log. The next
	# generation triggers another attempt.
	last_reload=$target
}

last_pending=
last_reload=
log "watching $GENS every ${INTERVAL}s"
while :; do
	check_pending
	check_current
	sleep "$INTERVAL"
done
