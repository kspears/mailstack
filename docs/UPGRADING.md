# Upgrading

Third-party software is updated by hand, one image at a time, on purpose: a mail server is
not something to let a bot bump. Nothing here follows a floating tag.

## Where the pins live

| Component | Pin | File |
|---|---|---|
| postfix (via Debian) | `debian:trixie-slim` tag and digest | `images/postfix/Dockerfile` |
| mailctl build | `golang:<version>-trixie` tag and digest | `images/admin/Dockerfile` |
| mailctl runtime | `gcr.io/distroless/static-debian13` digest (no version tags exist) | `images/admin/Dockerfile` |
| dovecot | `dovecot/dovecot:<version>-root` tag and digest | `deploy/ci/compose.yaml` and the deployment's compose file |
| rspamd | `rspamd/rspamd:<version>` tag and digest | same |
| redis | `redis:<version>-alpine` tag and digest | same |
| test client | `python:<version>-slim` tag and digest | `deploy/ci/compose.yaml` |

The postfix package itself is whatever Debian ships on the pinned base image's suite at
build time, so rebuilding the same digest on another day can pull a newer point release.
Release images are built once, tagged, and deployed by tag; do not rebuild to "refresh".

Every pin is written `image:tag@sha256:...`. The tag says what was meant; the digest is what
runs. When they disagree, the digest wins.

## Getting a digest

```
docker buildx imagetools inspect dovecot/dovecot:2.4.5-root
```

Use the top-level `Digest:` line (the multi-arch index), and check that both
`linux/amd64` and `linux/arm64` appear in the platform list. Pinning a single-platform
manifest breaks the other architecture.

## Procedure, one image at a time

Never move two pins in one change; when the test fails you need to know which one did it.

1. **Read the release notes** for every version between the current pin and the target,
   not just the last one.
   - Debian and postfix: <https://www.postfix.org/announcements.html> and the Debian
     package changelog linked from <https://tracker.debian.org/pkg/postfix>.
   - dovecot: <https://github.com/dovecot/core/releases> and
     <https://doc.dovecot.org/> (the "Upgrading" and "Settings changes" pages for the 2.4 series).
   - rspamd: <https://github.com/rspamd/rspamd/blob/master/ChangeLog> and
     <https://rspamd.com/announce/>.
   - redis: <https://github.com/redis/redis/releases>.
   - Go and distroless: <https://go.dev/doc/devel/release> and
     <https://github.com/GoogleContainerTools/distroless/releases>.
2. **Change the one pin**: tag and digest together, in every file that names that image.
3. **Run `deploy/ci/test.sh`.** It builds both images, brings up the reference stack, and
   proves delivery, IMAPS login, spam filing, open-relay refusal, unknown-recipient
   refusal and forged-sender refusal. A dovecot or rspamd config setting that the new
   version renamed or dropped fails here, not in production.
4. **Apply** on a rehearsal box first when one exists; otherwise in a quiet window.
   Pull the new image, then recreate only that service:
   `docker compose pull <service> && docker compose up -d <service>`.
5. **Verify** on the live stack:
   - `docker compose ps` shows every service running, with no restart loop.
   - Send yourself a message from outside and read it over IMAPS.
   - Send one out through the relay and confirm it arrives.
   - Check the logs of the service you changed for new warnings (`docker compose logs --since 10m <service>`).
   - For postfix, `mailctl` changes still apply: make a throwaway alias and remove it; the
     `ok:` line proves the watcher round trip.
   - For dovecot, confirm an existing message still opens (encrypted and compressed
     mail is where a format change would show).
   - For rspamd, confirm a known spam sample still lands in Junk, and that the
     thresholds (`reject 15`, `add_header 6`, `greylist 4`) read back from `rspamadm configdump actions`.
6. **Roll back** by putting the previous tag and digest back and recreating the service.
   Keep the old line in the commit message so it is one copy away. Redis and rspamd data
   forward-migrate rarely; read the release notes for that before assuming a downgrade is
   clean.

## Dovecot: storage version

`dovecot_storage_version` in `dovecot.conf` is the on-disk format dovecot writes.
**Keep it at the oldest version you might roll back to.** An upgrade that moves it forward
can write indexes and mail files the previous version cannot read, which turns a rollback
into a restore from backup. Raise it deliberately, in its own change, only after the old
version can no longer be a rollback target. `dovecot_config_version` is separate: it
selects the defaults the configuration was written against, and new versions still accept
older values.

Mail is encrypted with a site key pair (`crypt_global_*`). Back up the private key
with the mail; without it every stored message is unreadable.
