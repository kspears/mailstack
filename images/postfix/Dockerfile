# Debian's postfix package, nothing else baked in. main.cf and master.cf are mounted at run
# time so the same image serves CI and production. Pinned by tag and digest: the tag says
# what was meant, the digest is what is actually built. See docs/UPGRADING.md.
FROM debian:trixie-slim@sha256:a72b4433de1cf7d6bae0c4cee74d0547f58601a643b3375f070c51600d63b6b2

# libsasl2-modules provides PLAIN/LOGIN for authenticating to an upstream relay;
# ca-certificates lets smtp_tls_CAfile verify it. Nothing else is needed.
# The postfix postinst writes a throwaway main.cf from debconf answers; the mounted one wins.
RUN apt-get update \
 && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
      postfix ca-certificates libsasl2-modules \
 && rm -rf /var/lib/apt/lists/*

COPY entrypoint.sh watcher.sh /usr/local/bin/
RUN chmod 0755 /usr/local/bin/entrypoint.sh /usr/local/bin/watcher.sh

# The queue directory is a volume in every deployment; the entrypoint repairs its ownership.
VOLUME /var/spool/postfix
EXPOSE 25 465 587

ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
