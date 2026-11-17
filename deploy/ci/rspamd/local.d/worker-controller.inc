# Web UI and control API. Loopback only: this stack publishes nothing from rspamd, and the
# container's own healthcheck talks to 127.0.0.1.
bind_socket = "127.0.0.1:11334";
