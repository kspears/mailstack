require ["fileinto", "mailbox"];

# rspamd's milter proxy adds this header when the score reaches add_header.
if header :is "X-Spam" "Yes" {
  fileinto :create "Junk";
  stop;
}
