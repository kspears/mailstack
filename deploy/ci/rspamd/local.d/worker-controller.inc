# Web UI and control API. Reachable only on the compose network (nothing publishes 11334), so
# dovecot's Sieve `mailctl learn` can train it; every address except localhost must send the
# password. The container's own healthcheck talks to 127.0.0.1, which needs none.
bind_socket = "*:11334";
# `password` and `enable_password` are generated per test run into .keys/rspamd and never committed.
.include "/etc/rspamd/secrets/controller.inc"
