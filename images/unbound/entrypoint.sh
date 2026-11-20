#!/bin/sh
# Refuse to start on a config unbound would reject, with its own message, then run in the
# foreground. unbound binds port 53 as root and drops to the `unbound` user itself.
set -eu
conf=/etc/unbound/unbound.conf
[ -f "$conf" ] || { echo "FATAL: $conf is missing; mount the deployment's unbound.conf there" >&2; exit 1; }
unbound-checkconf "$conf"
exec unbound -d -c "$conf"
