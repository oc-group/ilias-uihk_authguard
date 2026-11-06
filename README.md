# AuthGuard plugin for ILIAS

[![DOI](https://zenodo.org/badge/DOI/10.5281/zenodo.22028606.svg)](https://doi.org/10.5281/zenodo.22028606)

Blocks automated (bot) submissions of the ILIAS self-registration form, and offers the same
protection to other plugins that publish forms to anonymous visitors. ILIAS core shipped a
Securimage-based CAPTCHA on self-registration through ILIAS 7 and
[removed it in ILIAS 8](https://docu.ilias.de/go/wiki/wpage_7029_1357), on the grounds that it no
longer kept bots out. This plugin reimplements the protection as a `uihk` plugin, built from checks
that ask a visitor for nothing, with an image CAPTCHA only as the fallback when JavaScript is off.

## What it checks

A form is accepted only if it passes, in this order:

1. **Submit timing.** A submit arriving less than two seconds after the form was rendered is
   rejected: nobody fills a form in that fast.
2. **Honeypot.** A hidden decoy input, named differently for every session and form, must stay
   empty. It is hidden from screen readers and keyboard navigation (`aria-hidden`, `tabindex`),
   so it never traps a visitor using assistive technology.
3. **Challenge provider.** One challenge, chosen by the administrator on the plugin's
   configuration screen (see "Challenge providers" below). The default is a proof-of-work: the
   [Altcha](https://altcha.org) widget solves a small computational challenge in the background as
   soon as the page loads, and the visitor clicks nothing.
4. **Image CAPTCHA, only without JavaScript.** A visitor whose browser runs no scripts sees a
   distorted-text image and a field for it, and must answer correctly.

Every check state is held in the ILIAS session under the form's own id, so two protected forms in
one session never interfere, and every verification is single use. Every rejection shows the visitor
the same message, whichever check failed; the specific reason goes only to the ILIAS log.

## Challenge providers

The administrator picks one provider under `Administration` -> `Extending ILIAS` -> `Plugins` ->
AuthGuard -> `Configure`. Altcha is the default and needs no setting. Each external provider needs
the keys issued by its vendor, which are stored as ILIAS settings; the secret is stored encrypted.
A provider whose keys are incomplete is not used: the Altcha check runs instead, and the ILIAS log
says so.

**When the vendor cannot be reached.** By default an external provider fails closed: if the
server cannot get an answer from the vendor, the submit is rejected. The checkbox "Accept submits
when the vendor cannot be reached" in the same section turns this around, for all external
providers at once (it has no effect on Altcha, which runs on the server). "Cannot be reached" means
only that the verification request failed: a connection error, a timeout, a TLS error, an HTTP 5xx
status, or an answer that is not readable JSON. A well-formed answer from the vendor that refuses
the visitor (invalid, expired or reused token, wrong action, reCAPTCHA v3 score below the
threshold) is always a rejection, and so is a 4xx status, which points at a wrong key on our side.
Timing and honeypot checks run first and reject regardless, and a visitor whose widget sent no
answer still gets the image CAPTCHA. Every submit accepted this way is written to the ILIAS log at
warning level with the provider and the form id (`submit accepted without a vendor check`), so a
skipped protection is visible. Leave the checkbox off unless a vendor outage that locks visitors
out is worse for you than the protection being absent while it lasts.

| Provider | Challenge | Data sent to the vendor |
|---|---|---|
| Altcha (default) | proof of work, no click | none |
| Google reCAPTCHA v2 | checkbox | yes |
| Google reCAPTCHA v3 | invisible, score based; the score threshold is configurable (default 0.5) | yes |
| Cloudflare Turnstile | widget, usually no click | yes |
| hCaptcha | checkbox | yes |
| Friendly Captcha | proof of work, no click; global or EU endpoint | yes |

The configuration screen has a button, below the form, that opens one dialog with a draft text for
the privacy policy of the site for each external provider, and under each draft a list of what to
check or complete before using it. The drafts are in English, to be translated into the language
of the site's privacy policy; they are starting points with placeholders for the operator's data,
to be reviewed by the data protection officer or a lawyer, and are not legal advice.

The Friendly Captcha widget (npm package `@friendlycaptcha/sdk`) is served from the plugin, like the
Altcha widget; the other external widgets are loaded from the vendor. In every case the browser
still contacts the vendor, and the vendor verifies the answer with the server.

## Privacy by design

With the default provider (Altcha) everything is generated and verified on the ILIAS server; the
widget script is shipped with the plugin and loaded from the same host. No request is made to any
third-party service and no user data leaves the installation. **External providers (Google
reCAPTCHA v2 and v3, Cloudflare Turnstile, hCaptcha, Friendly Captcha) send data about the visitor
to the vendor** (at least the visitor's answer and, with the vendor's script, whatever that script
collects), so the privacy policy of the installation must name the vendor before one of them is
selected. The plugin sets no cookies of its own and stores no personal data and no database rows
for visitors: it keeps a render timestamp, the honeypot name, a random secret for the proof-of-work
challenges and the expected CAPTCHA answer in the ILIAS session that already exists, and all of it
is discarded with the session. A rejected submission is written to the ILIAS log with the form id
and the reason, nothing else.

## Accessibility

The honeypot and the timing check are invisible to assistive technology, and the default
proof-of-work asks the visitor to do nothing, so none of the three is a barrier. The external
providers have their own accessibility properties, which are the vendors' statements and have not
been audited for this plugin; reCAPTCHA v2 and hCaptcha may show an image challenge. The image
CAPTCHA, shown only when JavaScript is off, is image-only and does not meet WCAG 2.1 success
criterion 1.1.1 (Non-text Content, Level A), which requires a CAPTCHA to be available in more than
one modality; there is no audio alternative yet. Installations subject to EN 301 549 should provide
an alternative registration route, assisted registration on request for example, and state it on
the page.

## For plugin developers

Other plugins protect their own forms through one class, `ilAuthGuardFormProtection`:

```php
if (class_exists("ilAuthGuardFormProtection") && ilAuthGuardFormProtection::isAvailable(1)) {
    $protection = new ilAuthGuardFormProtection();

    // when building the form: the returned HTML goes inside the <form>
    $html = $protection->render("my-form");

    // when saving: pass the PSR-7 request, decide yourself how to fail
    $result = $protection->verify("my-form", $DIC->http()->request());
    if (!$result->isPassed()) {
        // show $result->getMessage(), re-render the form (which renders a new challenge)
    }
}
```

`isAvailable()` is true only when AuthGuard is installed, active and offers the requested API
version (`ilAuthGuardFormProtection::API_VERSION`, currently 1). The form id is a string of
lowercase letters, digits, `_` and `-`, up to 64 characters. `verify()` consumes the form's state
whatever the outcome, so after a failure the form must be rendered again. The full contract, the
failure reasons, a worked example for a legacy `ilPropertyFormGUI` and the versioning policy are in
the integration guide kept with the plugin's documentation in the OC wiki workspace.

## Credits

Developed by **OC Open Consulting SB Srl** as part of the Horizon Europe project
[**DIAMETER**](https://www.diameter-eu.org/).

![Funded by the European Union](docs/FundedbytheEU_logo.png)

Funded by the European Union under Grant Agreement No 101177422. Views and opinions expressed are
however those of the author(s) only and do not necessarily reflect those of the European Union or
the European Commission. Neither the European Union nor the granting authority can be held
responsible for them.

## License

GNU General Public License v3.0 or later (see [LICENSE](LICENSE)).

The proof-of-work widget is [Altcha](https://altcha.org) (MIT), installed as the npm dependency
`altcha` (see `package.json`); the server side uses `altcha-org/altcha` (MIT) through Composer. The
Friendly Captcha widget is the npm dependency `@friendlycaptcha/sdk` (MPL-2.0), used unmodified.

## Reporting a security issue

By e-mail to plugins@oc-group.eu, not as a public issue (see [SECURITY.md](SECURITY.md)).

## Installation

### Download the plugin

From the ILIAS directory, run:

```sh
mkdir -p public/Customizing/global/plugins/Services/UIComponent/UserInterfaceHook
cd public/Customizing/global/plugins/Services/UIComponent/UserInterfaceHook
git clone -b release_11 https://github.com/oc-group/ilias-uihk_authguard AuthGuard
```

### Install Composer dependencies

```sh
cd AuthGuard
composer install --no-dev
```

### Install the front-end dependencies

```sh
npm install
```

Run it from the plugin directory (`AuthGuard`), next to `composer install`. ILIAS installs a plugin
with `composer du` only and runs no npm step, so the Altcha widget (`node_modules/altcha`) and the
Friendly Captcha widget (`node_modules/@friendlycaptcha/sdk`) are not there until you do this.
Without Altcha the widget script answers 404, the `<altcha-widget>` element is never defined and no
proof-of-work is submitted. The image CAPTCHA is rendered only for visitors without JavaScript, so
every visitor with JavaScript is rejected on the protected form (registration included) until
`npm install` has been run.

### Install the plugin

Return to the ILIAS directory and run:

```sh
composer du
```

Then activate the plugin:

1. Go into `Administration` -> `Extending ILIAS` -> `Plugins`
2. Look for the name of this plugin
3. Click on `Actions` -> `Install`
