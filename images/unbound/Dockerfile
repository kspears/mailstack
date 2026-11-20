# Debian's unbound package as a recursive resolver for postfix's postscreen and rspamd.
# Blocklist operators refuse or rate-limit queries that arrive through large shared
# resolvers (a cloud provider's, a public one), so the stack asks the root servers itself.
# unbound.conf is mounted at run time, as postfix's main.cf is. Pinned by tag and digest;
# see docs/UPGRADING.md.
FROM debian:trixie-slim@sha256:a72b4433de1cf7d6bae0c4cee74d0547f58601a643b3375f070c51600d63b6b2

# dns-root-data ships the root hints and the DNSSEC root trust anchor as files, so the
# resolver needs no writable anchor and no network fetch at start. The package's own
# unbound.conf is removed so that a missing mount fails loudly instead of starting on
# Debian's defaults.
RUN apt-get update \
 && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
      unbound dns-root-data \
 && rm -rf /var/lib/apt/lists/* /etc/unbound/unbound.conf /etc/unbound/unbound.conf.d

COPY entrypoint.sh /usr/local/bin/
RUN chmod 0755 /usr/local/bin/entrypoint.sh

# Healthy once unbound answers its control channel, which the mounted config must enable on
# 127.0.0.1 (see deploy/ci/unbound/unbound.conf).
HEALTHCHECK --interval=5s --timeout=3s --retries=12 \
  CMD ["unbound-control", "-c", "/etc/unbound/unbound.conf", "status"]

ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
