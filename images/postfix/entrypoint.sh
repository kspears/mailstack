#!/bin/sh
# Prepare the queue directory, start the generation watcher, then become postfix.
set -eu

# The queue is a volume, so a fresh one is empty and an old one may have stale ownership.
# `postfix check` creates missing queue subdirectories and repairs owners and modes. Not
# `set-permissions`: it also chowns main.cf and master.cf, which are mounted read-only.
# It also copies resolv.conf, services and friends into the queue directory, which Docker
# rewrites on every container start.
postfix check

# The watcher must outlive its own crashes: without it no generation is ever accepted and every
# mailctl change times out. Restart it with a pause so a persistent fault cannot spin.
(
	while :; do
		status=0
		/usr/local/bin/watcher.sh || status=$? # not bare: `set -e` would end this loop with it
		echo "entrypoint: watcher exited with status $status; restarting in 1s"
		sleep 1
	done
) &

# exec so postfix is PID 1 and receives SIGTERM for a graceful stop.
exec postfix start-fg
