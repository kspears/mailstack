require ["vnd.dovecot.pipe", "copy", "imapsieve"];

# Runs when a user moves or copies a message into Junk: train rspamd on it as spam.
pipe :copy "mailctl" ["learn", "spam"];
