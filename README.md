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
3. **Proof-of-work.** The [Altcha](https://altcha.org) widget solves a small computational
   challenge in the background as soon as the page loads. The visitor clicks nothing.
4. **Image CAPTCHA, only without JavaScript.** A visitor whose browser runs no scripts sees a
   distorted-text image and a field for it, and must answer correctly.

Every check state is held in the ILIAS session under the form's own id, so two protected forms in
one session never interfere, and every verification is single use.

## Privacy by design

Everything is generated and verified on the ILIAS server; the widget script is shipped with the
plugin and loaded from the same host. No request is made to any third-party service and no user data
leaves the installation. The plugin sets no cookies of its own and stores no personal data and no
database rows: it keeps a render timestamp, the honeypot name, a random secret for the
proof-of-work challenges and the expected CAPTCHA answer in the ILIAS session that already exists,
and all of it is discarded with the session. A rejected submission is written to the ILIAS log with
the form id and the reason, nothing else.

## Accessibility

The honeypot and the timing check are invisible to assistive technology, and the proof-of-work asks
the visitor to do nothing, so none of the three is a barrier. The image CAPTCHA, shown only when
JavaScript is off, is image-only and does not meet WCAG 2.1 success criterion 1.1.1 (Non-text
Content, Level A), which requires a CAPTCHA to be available in more than one modality; there is no
audio alternative yet. Installations subject to EN 301 549 should provide an alternative
registration route, assisted registration on request for example, and state it on the page.
The Altcha widget's own accessibility claims are the vendor's statement and have not been audited
for this plugin.

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

GNU General Public License v3.0 or later — see [LICENSE](LICENSE).

## Reporting a security issue

By e-mail to plugins@oc-group.eu, not as a public issue — see [SECURITY.md](SECURITY.md).

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

### Install the plugin

Return to the ILIAS directory and run:

```sh
composer du
```

Then activate the plugin:

1. Go into `Administration` -> `Extending ILIAS` -> `Plugins`
2. Look for the name of this plugin
3. Click on `Actions` -> `Install`
