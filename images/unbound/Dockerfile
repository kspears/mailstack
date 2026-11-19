# Debian's unbound package as a recursive resolver for postfix's postscreen and rspamd.
# Blocklist operators refuse or rate-limit queries that arrive through large shared
# resolvers (a cloud provider's, a public one), so the stack asks the root servers itself.
# unbound.conf is mounted at run time, as postfix's main.cf is. Pinned by tag and digest;
# see docs/UPGRADING.md.
FROM debian:trixie-slim@sha256:a72b4433de1cf7d6bae0c4cee74d0547f58601a643b3375f070c51600d63b6b2

# dns-root-data ships the root hints and the DNSSEC root trust anchor as files, so the
# resolver needs no writable anchor and no network fetch at start.
RUN apt-get update \
 && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
      unbound dns-root-data \
 && rm -rf /var/lib/apt/lists/*

COPY entrypoint.sh /usr/local/bin/
RUN chmod 0755 /usr/local/bin/entrypoint.sh

EXPOSE 53/udp 53/tcp

ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
