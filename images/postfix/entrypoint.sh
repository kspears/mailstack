#!/bin/sh
# Prepare the queue directory, start the generation watcher, then become postfix.
set -eu

# The queue is a volume, so a fresh one is empty and an old one may have stale ownership.
# `postfix check` creates missing queue subdirectories and repairs owners and modes. Not
# `set-permissions`: it also chowns main.cf and master.cf, which are mounted read-only.
# It also copies resolv.conf, services and friends into the queue directory, which Docker
# rewrites on every container start.
postfix check

/usr/local/bin/watcher.sh &

# exec so postfix is PID 1 and receives SIGTERM for a graceful stop.
exec postfix start-fg
