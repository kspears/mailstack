# Admin status page

Status: Reviewed
Date: 2026-11-20
Summary: A status page, built only from files mailctl can already read, that answers "is mail working?" from a phone, plus last-delivery and size per mailbox and a phone-friendly admin UI.

## Problem and goals

The admins (Kevin and his brothers) support family members who use the server. When someone calls
with "my email isn't working", the admin needs to answer two questions from an iPhone, without
SSH, in under a minute:

1. Is the server healthy right now?
2. Has mail been arriving for this person?

Goals:

- A Status page that is the UI's home page and gives one overall verdict with the reasons.
- Every signal comes from files the `ui` container already mounts (`state` and `vmail:ro`). The
  stack gets no new container, network, daemon or privilege.
- The Mailboxes list shows each mailbox's last delivery and size, so "did anything arrive for
  Mom?" is answered on the list itself.
- Every admin page is usable on an iPhone 17 Pro Max and on a desktop browser.

Success: from an iPhone, a signed-in admin can tell whether mail is working and when mail last
reached a given mailbox, in under a minute, without SSH.

## Non-goals

Out of scope for good (kept out on purpose, to keep the stack simple):

- Any new container, host helper, or root process. That includes a status collector and a
  fail2ban unban button.
- Reading or parsing daemon logs.
- Checks that need the network: DNS records, blocklists, TLS certificate expiry, outside
  reachability of SMTP and IMAP. An external monitor covers these, set up outside this repo.
- Any direct check of dovecot, rspamd, redis or unbound. The page cannot see them; the external
  monitor covers reachability.
- History, charts or trends. The page shows current values only.
- Auto-refresh. The admin reloads the page to refresh it.

Deferred (may come later, each needs its own spec):

- Push alerts (Pushover is the likely choice).
- Message trace by sender or recipient.
- A mailbox detail page with logins, devices and failed logins.
- Phone setup by QR code or `.mobileconfig`, quotas, app passwords.
- `docs/OPERATIONS.md` covering the external monitor, fail2ban tuning, and an iOS "Unban" Shortcut.

## Users and flows

Users: every admin. All admins are equal and see the same pages. Nothing on these pages changes
state, so nothing new goes in the change log.

### Status page

1. The admin signs in (passkey, or password and code), or opens `/` while already signed in.
2. They land on `/status`. The nav shows a `Status` link first, before `Mailboxes`.
3. At the top is one verdict line: `No problems found`, `Needs attention` or
   `Something is wrong`, on a green, yellow or red background. Under it is one line per yellow or
   red reason, red first, then in the card order below. Under the reasons, in muted text:
   `This page checks postfix's watcher, the account files and disk space. It does not check
   dovecot, spam filtering or the outside world.`
4. Below that is one card per check, in this order. Each card has a mark: green, yellow, red, or
   neutral (no colour, information only). Each card shows a one-line value:
   - **Postfix watcher**: `Last seen 12 s ago`.
   - **Account files**: `In use: <generation id>`, plus `Matches the account store`. When `watcher/status` reports an error for a generation other than the one in use, a second line reads `Last change was rejected: <message>`.
   - **Pending change**: `None`, or `<generation id>, waiting <age>`.
   - **Last mail in**: `<time> (<age> ago)`, the newest delivery across all mailboxes.
   - **Disk**: one card per distinct filesystem. If `MAILCTL_MAIL_ROOT` and `MAILCTL_STATE` are
     on the same filesystem, there is one card titled `Mail and state disk`. Otherwise there are
     two, `Mail storage disk` and `State disk`. Each shows `<used> of <size> used (<percent>%)`.
5. At the bottom: `Checked at <time>` (when the page was built) and `Mail scanned at <time>` (when the
   cached mail scan ran). Reloading the page refreshes it.

### Mailboxes list

1. The admin opens Mailboxes.
2. Each mailbox row keeps its address, state and name, and adds a line:
   `Last delivery <age> ago · <size>`, or `No mail yet · <size>` when the mailbox has no
   delivered message.
3. Tapping the row opens the existing edit page, as today.

### Phone use

Every existing page (Mailboxes, Aliases, Domains, Send-as, Log, account, sign-in, enrolment) and
the new Status page work at iPhone 17 Pro Max width in portrait, with no sideways page scroll. Wide
tables may scroll inside their own box, as the Log table does today. Long unbroken text (generation
ids, watcher error lines with paths) wraps rather than widening the page.

## Data and interfaces

### Postfix watcher heartbeat (new)

- `images/postfix/watcher.sh` updates `watcher/heartbeat` once per pass of its main loop. The
  file's mtime is the heartbeat. The content is the UTC time in RFC 3339 form plus a newline, for
  humans reading the file.
- The file is written the way `write_status` writes `status`: to a temporary file in `watcher/`,
  then renamed.
- A failed write does not stop the loop. It is logged with the existing `log` function only when
  the write goes from working to failing, and once more when it recovers, never on every pass.
- Nothing else in the watcher changes.

### Status checks (read by `mailctl serve`)

| Check | Source | Green | Neutral | Yellow | Red |
|---|---|---|---|---|---|
| Postfix watcher | mtime of `<state>/watcher/heartbeat` | updated within the last 5 minutes | `MAILCTL_WATCHER=off`: `Watcher is off` | file missing: `Postfix watcher has not reported yet` | older than 5 minutes: `Postfix watcher last seen <age> ago` |
| Account files | `generations/current` compared with what the store renders (below) | match | `current` missing: `No account files yet`. Change lock busy: `A change is being applied` | | no match, or `current` unreadable: `The files in use do not match the account store; run "mailctl apply" after checking "mailctl mailbox list"` |
| Pending change | `generations/pending` symlink; age is the `Lstat` mtime of the link | absent: `None` | present and not older than `MAILCTL_APPLY_TIMEOUT`: `<generation id>, waiting <age>`. `MAILCTL_WATCHER=off`: `Watcher is off` | present and older than `MAILCTL_APPLY_TIMEOUT`: card `<generation id>, waiting <age>`, reason `A change has been pending for <age>` | |
| Last mail in | newest last delivery across all mailboxes (below) | newest delivery within the last 2 hours | no delivery in any mailbox: `No mail yet` | newest delivery 2 hours ago or older: `No mail received for <age>`. One or more mailboxes could not be read: `<n> mailboxes could not be read` | |
| Disk | `syscall.Statfs` on `MAILCTL_MAIL_ROOT` and on `MAILCTL_STATE` | under 80% used | | 80% to under 90%: `<card title> is <percent>% full` | 90% or more: `<card title> is <percent>% full`. `Statfs` fails: `Cannot read <card title>: <reason>` |

The overall verdict is the worst of the green, yellow and red marks. Neutral marks never change it.
If all marks are green or neutral, the verdict is `No problems found`.

A rejected change shows on the Account files card, not on a card of its own: on a healthy server
the watcher's last verdict names the generation in use, so a separate card only repeated it. The
rejection is history, since mailctl rolled the change back and reported it then, so it never
changes the card's mark.

**Account files check.** Today the comparison is `requireCurrentMatches` in
`internal/generate/apply.go`. It is unexported, and it runs inside a change, under the change lock.
The Status page needs an exported, read-only form of it on `generate.Admin`. That form:

- Takes the change lock shared and non-blocking (`flock` `LOCK_SH|LOCK_NB` on `<state>/lock`). If
  a change holds the lock, it does not wait: the card is neutral, `A change is being applied`. This
  avoids the window in which `current` has moved but the store transaction has not yet committed.
- Reads the store snapshot and `generations/current` while holding the shared lock, and releases it
  before rendering the page.
- Reports three outcomes: no `current` yet, match, or mismatch (with the reason when `current` cannot be read).
- Is computed on every request and never cached.

`web` also needs the apply timeout and whether the watcher is off. Both are already in the
`generate` config. Expose them read-only alongside the new method. Do not read the environment a
second time.

**Disk.** `used = Blocks − Bfree`. `percent = used / (used + Bavail) × 100`, the same figure `df`
shows. Thresholds compare the unrounded percent. The displayed percent is rounded down to a whole
number, so the number shown never crosses a threshold the mark has not. Two paths are on the same filesystem
when their `Stat` device ids match. The code must build on both linux (production) and darwin
(`just dev`).

### Last delivery and size per mailbox

- The mailboxes scanned are the store's mailboxes, every state included. Directories on disk for
  removed mailboxes are ignored.
- A mailbox's directory is `MailPath(address)` (`<MAILCTL_MAIL_ROOT>/<domain>/<localpart>`),
  with dovecot's `mail_path = ~/Maildir`.
- **Last delivery** is the newest mtime of any regular file in the Inbox's `new` and `cur`
  directories and the Junk folder's `new` and `cur` directories. Delivery writes only to those two
  folders; Junk gets mail through `spam.sieve`. In the reference config, Inbox is `Maildir/new` and
  `Maildir/cur`. Junk is the folder dovecot creates for `fileinto "Junk"`: `Maildir/.Junk` under
  the Maildir++ layout. The implementer confirms the actual path against the running reference stack.
  The integration test (below) fails if the path is wrong. Other folders are left out, so a message
  the user saves to Sent or Drafts does not count as a delivery.
- **Size** is the sum of `st_blocks × 512` over all regular files under the mailbox directory: size
  on disk. Mail is stored encrypted and compressed (`mail_crypt`), so this is not the message size.
  It is rendered in binary units with one decimal place (`512 B`, `1.5 KiB`, `3.2 MiB`, `1.1 GiB`).
- A mailbox whose directory does not exist, or whose mail root does not exist, shows
  `No mail yet · 0 B`. That is not an error.
- A mailbox whose directory exists but cannot be fully read shows `Cannot read mail folder` in place
  of its line. It also counts toward the `<n> mailboxes could not be read` note on the Status page.
- **Last mail in** on the Status page is the newest last delivery across all readable mailboxes, or
  `No mail yet` if there is none.
- **Cache.** The scan of all mailboxes is cached in memory for 60 seconds and shared by the Status
  page and the Mailboxes list. One scan runs at a time: concurrent requests that find the cache
  expired wait for the same scan, they do not start their own. A mailbox that is not in the cached
  result (added since the scan) is scanned on its own during that request and added to the cache.

### Formats

- Ages, rounded down: under 60 seconds `<n> s`; under 60 minutes `<n> min`; under 48 hours
  `<n> h`; otherwise `<n> days`.
- Every time the UI shows is in Pacific time (`America/Los_Angeles`), formatted
  `2006-01-02 15:04 MST`, so it reads `2026-11-20 14:05 PST`, or `PDT` in summer. That covers the
  Status page, the Mailboxes list, and the existing Log page: the `stamp` template function in
  `internal/web/server.go` changes from UTC to Pacific. The zone is fixed in code, with no new
  setting. The admin image is distroless, with no zone files, so the binary embeds the zone
  database by importing `time/tzdata` (standard library). Stored times stay UTC.

### Routes, templates and redirects

- New `GET /status`, rendered from a new `internal/web/templates/status.html`, using the existing
  `head` and `foot` templates and the existing card styles.
- Every place that sends a signed-in admin to `/mailboxes` as a landing page now sends them to `/status`:
  - `GET /` (`internal/web/server.go`);
  - the guard that redirects a signed-in visitor away from the sign-in pages (`internal/web/server.go`);
  - the password sign-in redirect (`internal/web/signin.go`);
  - the passkey sign-in's `data-next` (`internal/web/templates/signin.html`).

  Redirects back to `/mailboxes` after a mailbox change stay as they are.
- The nav in `layout.html` gains `Status` as its first link, with `aria-current="page"` when active.
- `mailboxes.html` gains the last-delivery and size line.
- The Status page loads no script. It gets the default CSP (`default-src 'none'`, as `/mailboxes`
  does), and no new CSP exceptions.

### Compose

`deploy/ci/compose.yaml` is unchanged. The `ui` service already mounts the whole `state` volume
(so it sees `watcher/` and `lock`) and `vmail` read-only.

## Edge cases and failure modes

- **Old postfix image without the heartbeat:** the watcher card is yellow,
  `Postfix watcher has not reported yet`. Nothing errors.
- **Watcher off** (`MAILCTL_WATCHER=off`, as in `just dev` and the CI bootstrap): the watcher and
  pending cards are neutral, `Watcher is off`. The page can still show `No problems found`.
- **Fresh install** (no `current`, no mail, no `watcher/status`): Account files `No account files yet`,
  Last mail in `No mail yet`. All neutral, and nothing turns
  red because of the fresh install alone.
- **Clock skew:** the heartbeat age is the UI's clock minus the file's mtime. If that comes out
  negative, the age is treated as 0 (`0 s ago`).
- **A change in progress while the page loads:** Account files is neutral, `A change is being
  applied`. Reloading after the change finishes shows the real result. That result is never cached.
- **A large mailbox:** the scan runs at most once per 60 seconds, whatever the number of
  requests. It has no time bound. On a server of a few dozen mailboxes, a full walk is accepted.
- **Mail that does not stay in Inbox or Junk:** if a mail client or filter moves mail out on arrival
  (archive on arrival, delete, a user Sieve rule), "last delivery" shows an older date or
  `No mail yet` while mail is in fact arriving. This is a known limit.
- **Mail imported from mailcow** keeps its original file times, so "last delivery" can predate the
  move to this server until new mail arrives.
- **A store and files mismatch** (a restored store): red on the Status page. The wording points at
  `mailctl apply`, the same fix the CLI gives.
- **Disk full or read-only:** heartbeat writes fail. The watcher logs that once, and the heartbeat
  goes stale, so the page goes red after 5 minutes. The disk card shows the cause.
- **No mailboxes or domains yet:** the page renders, and Last mail in shows `No mail yet`.
- **A signed-out visitor:** `/status` behaves like every other page (redirect to sign-in).

## Constraints

- Go standard library only for the new code.
- No new container, mount, network, environment variable, or dependency.
- Reads only. Nothing on the Status page or the new Mailboxes line changes state. The only lock
  taken is the shared, non-blocking lock above.
- The page loads no script and gets no new CSP exceptions.
- The existing visual style (`style.css` tokens, cards, light and dark themes) is kept. Yellow and
  red mark colours are added as tokens for both themes.
- Tests:
  - Unit tests in `internal/web` (or a small new package it uses) for the check rules, with an
    injectable clock and disk reader. They cover every boundary in the table: heartbeat at exactly
    5 minutes, last mail in at exactly 2 hours, disk at exactly 80% and 90%, pending at exactly the apply timeout, watcher off,
    a missing heartbeat, a missing `current`, and a missing `watcher/status`.
  - A unit test in `internal/generate` for the new read-only check: match, mismatch, no `current`,
    and lock busy (hold the lock exclusively in the test and expect the busy outcome without
    blocking).
  - Unit tests for the mail scan, using a temporary maildir tree: Inbox only, Junk only, a
    Sent-only mailbox (no delivery), a missing directory, and an unreadable directory. The
    unreadable case is skipped when the test runs as root.
  - Cache tests with a counting scanner: two sequential requests inside 60 seconds do one scan;
    concurrent requests on an expired cache do one scan; a mailbox missing from the cache is scanned
    alone.
  - Format tests for ages and sizes at each unit boundary.
  - Existing tests that expect a landing on `/mailboxes` after sign-in (`internal/web/signin_test.go`)
    are updated to `/status`.
  - The integration test (`deploy/ci/test.sh`) checks:
    - `watcher/heartbeat` is updated while postfix runs;
    - `/status` returns 200 for a signed-in admin;
    - after the existing "spam goes to Junk" step, the Junk folder's `new` or `cur` directory for
      `alice@example.test` holds a file, checked directly with `ls` in the dovecot container. This
      proves the real Junk folder path; alice's Mailboxes row alone does not, since she also gets
      Inbox mail;
    - the Mailboxes page shows a `Last delivery` line for `alice@example.test`.
- `just check` passes.

## Acceptance criteria

Criteria 5–15 are checked by the unit tests above, criteria 4 and 18 by the integration test, and
criterion 16 by a person.

1. Given a signed-in admin, when they open `/`, then they are redirected to `/status`.
2. Given a successful sign-in, by password and code or by passkey, the admin lands on `/status`.
3. Given a signed-in admin opening `/signin`, they are redirected to `/status`.
4. Given a running stack from `deploy/ci/compose.yaml`, when you run
   `docker compose exec postfix stat -c %Y /data/mailstack/watcher/heartbeat` twice, 3 seconds
   apart, then the second value is greater than the first.
5. Given a heartbeat older than 5 minutes, when `/status` is built, then the verdict is
   `Something is wrong` and the reasons include `Postfix watcher last seen <age> ago`.
6. Given no `watcher/heartbeat` file and the watcher not off, the watcher card is yellow:
   `Postfix watcher has not reported yet`.
7. Given `MAILCTL_WATCHER=off`, the watcher and pending cards are neutral (`Watcher is off`) and do
   not affect the verdict.
8. Given `generations/current` not matching the store, the Account files card is red, and the reasons
   include `The files in use do not match the account store`.
9. Given the change lock held exclusively, the Account files card is neutral (`A change is being applied`), and the page
   is returned without waiting for the lock.
10. Given `generations/pending` older than `MAILCTL_APPLY_TIMEOUT`, the Pending change card is
    yellow, showing `<generation id>, waiting <age>`, and the reasons include
    `A change has been pending for <age>`.
11. Given a filesystem at 79.9%, 80.0% and 90.0% used (from an injected disk reader), the disk
    card is green, yellow and red respectively. At 89.9% it reads `89%` and is yellow.
12. Given a mailbox with one file in the Junk folder's `new` and an older one in `Maildir/cur`, its
    Mailboxes row shows `Last delivery <age> ago`, using the age of the Junk file.
13. Given a mailbox whose only file is in `Maildir/.Sent/cur`, its row shows
    `No mail yet · <size>`, with a non-zero size. Given a mailbox with no directory, its row shows
    `No mail yet · 0 B`.
14. Given a newest delivery 1 h 59 min ago, the Last mail in card is green. At exactly 2 hours,
    it is yellow, and the reasons include `No mail received for 2 h`.
15. Given all marks green or neutral, the verdict line reads `No problems found` and shows no reason lines.
16. On Safari on an iPhone 17 Pro Max in portrait, or in a 440 px-wide viewport in desktop
    Safari's responsive design mode, a person scrolls each page and finds no sideways page scroll.
    The pages are Status, Mailboxes, Aliases, Domains, Send-as, Log, account, sign-in and enrolment.
    Include a Status page showing a 300-character watcher error line. Wide tables may scroll inside
    their own box.
17. The `/status` response carries the same `Content-Security-Policy` header as `/mailboxes`, and
    its HTML has no `<script>` element.
18. `just check` passes, and `deploy/ci/test.sh` passes, including the new heartbeat, `/status`
    and alice `Last delivery` checks.

## Decisions

| Decision | Choice | Why | Decided by |
|---|---|---|---|
| Overall scope | Lean: only signals from files the UI already reads | Keep the mail server simple; the full design needed a collector container, a root host helper and log parsing | User |
| Network checks (DNS, blocklists, TLS, reachability) | Left to an external monitor outside this repo | Better at it, and it still works when the server is down | User |
| Unban | Not in the UI | Needs a root host helper; an iOS Shortcut over SSH covers it | User |
| Alerts | Deferred; Pushover is the likely choice | User plans to take it up separately | User |
| Postfix heartbeat | Watcher updates `watcher/heartbeat` every pass | Without it, "quiet" and "dead" look the same | User |
| Last delivery per mailbox and server-wide | Yes | Answers "did anything arrive for Mom?" | User |
| Mailbox size on the list | Yes | | User |
| Home page | `/status`, after any sign-in too | | User |
| Admins | All equal | | User |
| Phone support | All pages, iPhone 17 Pro Max portrait, as well as desktop | | User |
| Thresholds | Heartbeat red over 5 min; disk yellow at 80%, red at 90% | Proposed in the interview and accepted | User |
| Mail-stopped threshold | Last mail in turns yellow when the newest delivery is 2 hours old or older | The server is busy; this is the only sign inbound mail has quietly stopped, since the page cannot see dovecot | User |
| Verdict wording | `No problems found`, not `All good`, plus a note on what is not checked | The page cannot see dovecot or rspamd, so "All good" would overclaim | Agent default |
| Neutral marks | Information-only cards, plus watcher-off and fresh-install states, never colour the verdict | A dev stack or a fresh install must not look broken | Agent default |
| Store-versus-files check | New exported read-only check under a shared, non-blocking lock; busy shows neutral; never cached | Avoids false reds during a change and never stalls the page | Agent default |
| Pending change threshold | Yellow when older than `MAILCTL_APPLY_TIMEOUT`; age from the link's mtime | A pending link that outlives the timeout means an apply died midway | Agent default |
| What counts as a delivery | Newest file in Inbox and Junk `new`/`cur` | Delivery writes only there; Sent and Drafts are user saves | Agent default |
| Mailboxes scanned | Store mailboxes only | Leftover mail of removed mailboxes is not a delivery | Agent default |
| Scan cache | 60 seconds, shared, one scan at a time, new mailboxes scanned alone | Fresh enough for a phone call, without a scan on every reload | Agent default |
| Disk percent | `df`-style, thresholds on the unrounded value, displayed rounded down; one card when both paths share a filesystem | Matches what `df` shows; avoids two identical cards | Agent default |
| Boundaries | Heartbeat red when older than 5 min (exactly 5 min is green); pending yellow when older than the timeout (exactly the timeout is neutral); last mail yellow at 2 h or older; disk yellow at 80.0% or more, red at 90.0% or more | Pins every edge so tests and code agree | Agent default |
| Missing mail root | When `MAILCTL_MAIL_ROOT` does not exist yet, the disk check reads the nearest existing parent directory | mailctl never creates it, so a fresh install or `just dev` would otherwise show a red disk | Agent default |
| Log page header | `Time (UTC)` becomes `Time` | Times are now Pacific | Agent default |
| Size | `st_blocks × 512`, binary units, one decimal | Size on disk is what fills the disk | Agent default |
| Time zone | Pacific (`America/Los_Angeles`) on every UI page, Log included; fixed in code | The admins and family are in Pacific time | User (zone); agent default (all pages, no setting) |
| Ages | Rounded down: `s`, `min`, `h`, `days` | | Agent default |
| Heartbeat write failures | Logged on change of state only | Avoids a log line every second on a full disk | Agent default |
| Read errors on the Status page | A heartbeat that exists but cannot be read is red `Cannot read the watcher heartbeat: <reason>`; a lock or store error during the files check is red `Cannot check the account files: <reason>`; a mailbox that cannot be read never counts toward Last mail in | Show the real fault instead of a misleading one | Agent default |
| `watcher/status` on the page | Read without following symlinks, only if it is a regular file, at most 4 KiB | The internet-facing postfix container can write that directory | Agent default |
| Auto-refresh | None | Pages load no script; reload is enough | Agent default |

## Open questions

- **Backup age** on the Status page: what runs backups, and does it leave a file the UI can read?
  Kevin to answer. Until then, backups are not shown.
- **`docs/OPERATIONS.md`** (external monitor, fail2ban `maxretry`/`bantime` tuning, iOS Unban
  Shortcut): wanted or not. Kevin to decide later.

## Existing code touched

| File | Change |
|---|---|
| `images/postfix/watcher.sh` | Extended: writes `watcher/heartbeat` each pass |
| `internal/generate/apply.go` | Extended: exported read-only store-versus-files check; read-only access to the apply timeout and watcher-off setting |
| `internal/web/server.go` | Extended: `GET /status`; `stamp` formats in Pacific time; `/` and the signed-in guard redirect there; Mailboxes list data gains last delivery and size |
| `internal/web/signin.go` | Extended: password sign-in redirects to `/status` |
| `internal/web/templates/signin.html` | Extended: passkey `data-next` is `/status` |
| `internal/web/templates/layout.html` | Extended: `Status` nav link |
| `internal/web/templates/mailboxes.html` | Extended: last-delivery and size line |
| `internal/web/templates/status.html` | New |
| `internal/web/static/style.css` | Extended: yellow and red tokens, wrapping for long text, phone-width fixes found while checking criterion 16 |
| `internal/web/signin_test.go` | Extended: landing-page expectations move to `/status` |
| `deploy/ci/test.sh` | Extended: heartbeat, `/status`, and alice `Last delivery` checks |
| `deploy/ci/compose.yaml` | Left alone |
| `README.md` | Extended: `watcher/heartbeat` in the state layout, a short Status page section |
