# Milter endpoint for postfix. Self-scan: the proxy worker scans messages itself instead of
# forwarding to a separate normal worker, so one container needs no second hop.
# Reachable only on the compose network; nothing publishes 11332.
bind_socket = "*:11332";
milter = yes;
timeout = 120s;
upstream "local" {
  default = yes;
  self_scan = yes;
}
