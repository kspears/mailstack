require ["vnd.dovecot.pipe", "copy", "imapsieve", "environment", "variables"];

# Runs when a user moves or copies a message out of Junk: train rspamd on it as ham, unless
# it is being thrown away.
if environment :matches "imap.mailbox" "*" {
  set "mailbox" "${1}";
}
if string "${mailbox}" "Trash" {
  stop;
}
pipe :copy "mailctl" ["learn", "--controller", "http://rspamd:11334", "--password-file", "/run/secrets/rspamd-controller-password", "ham"];
