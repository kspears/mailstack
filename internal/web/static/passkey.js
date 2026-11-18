// The only script in the UI. It runs a passkey exchange for any button that
// carries data-passkey ("get" to sign in or confirm, "create" to add one):
// fetch a challenge, hand it to the browser, post the answer, move on.
"use strict";
for (const button of document.querySelectorAll("button[data-passkey]")) {
  button.addEventListener("click", async () => {
    const d = button.dataset;
    const status = document.getElementById("passkey-status");
    const say = (text) => { status.textContent = text; };
    if (!window.PublicKeyCredential || !PublicKeyCredential.parseRequestOptionsFromJSON) {
      say("This browser does not support passkeys.");
      return;
    }
    button.disabled = true;
    try {
      let begin = d.begin;
      if (d.label) {
        begin += "?label=" + encodeURIComponent(document.getElementById(d.label).value);
      }
      const started = await fetch(begin, { method: "POST", headers: { "X-CSRF": d.csrf } });
      if (!started.ok) {
        say(await started.text());
        return;
      }
      const options = (await started.json()).publicKey;
      const credential = d.passkey === "create"
        ? await navigator.credentials.create({ publicKey: PublicKeyCredential.parseCreationOptionsFromJSON(options) })
        : await navigator.credentials.get({ publicKey: PublicKeyCredential.parseRequestOptionsFromJSON(options) });
      const finished = await fetch(d.finish, {
        method: "POST",
        headers: { "X-CSRF": d.csrf, "Content-Type": "application/json" },
        body: JSON.stringify(credential.toJSON()),
      });
      if (!finished.ok) {
        say(await finished.text());
        return;
      }
      location.assign(d.next);
    } catch (err) {
      say(err.name === "NotAllowedError" ? "Cancelled, or no passkey for this site on this device." : "The passkey could not be used.");
    } finally {
      button.disabled = false;
    }
  });
}
