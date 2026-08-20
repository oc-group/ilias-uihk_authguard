# AuthGuard plugin for ILIAS

Blocks automated (bot) submissions of the ILIAS self-registration form with a locally generated
image CAPTCHA. ILIAS core shipped a Securimage-based CAPTCHA on self-registration through ILIAS 7 and
[removed it in ILIAS 8](https://docu.ilias.de/go/wiki/wpage_7029_1357), on the grounds that it no
longer kept bots out. This plugin reimplements the protection as a `uihk` plugin -- see
[Accessibility](#accessibility) below for what that inherits, and where the plugin is going instead.

## Privacy by design

The CAPTCHA image is generated entirely on the ILIAS server. No request is made to any third-party
service and no user data leaves the installation. The plugin sets no cookies of its own and stores no
personal data: it keeps the expected answer, a generation timestamp and a render timestamp in the
ILIAS session that already exists, and all three are discarded with the session.

## Accessibility

This release offers an image-only challenge and therefore does not meet WCAG 2.1 success criterion
1.1.1 (Non-text Content, Level A), which requires a CAPTCHA to be available in more than one
modality. There is no audio or non-visual alternative yet.

Installations subject to EN 301 549 should provide an alternative registration route -- assisted
registration on request, for example -- and state it on the registration page.

The direction for future releases is not a more accessible puzzle but **checks that ask the visitor
for nothing**, which are neutral for assistive technology because there is nothing to perceive or
operate. The first of them ships here: a submission arriving faster than a person could have typed is
rejected without anyone being asked to prove anything.

## Credits

Developed by **OC Open Consulting SB Srl** as part of the Horizon Europe project
[**DIAMETER**](https://www.diameter-eu.org/).

![Funded by the European Union](docs/FundedbytheEU_logo.png)

Funded by the European Union under Grant Agreement No 101177422. Views and opinions expressed are
however those of the author(s) only and do not necessarily reflect those of the European Union or
the European Commission. Neither the European Union nor the granting authority can be held
responsible for them.

## License

GNU General Public License v3.0 or later -- see [LICENSE](LICENSE).

## Reporting a security issue

By e-mail to plugins@oc-group.eu, not as a public issue -- see [SECURITY.md](SECURITY.md).

## Installation

### Download the plugin

From the ILIAS directory, run:

```sh
mkdir -p Customizing/global/plugins/Services/UIComponent/UserInterfaceHook
cd Customizing/global/plugins/Services/UIComponent/UserInterfaceHook
git clone -b release_9 https://github.com/oc-group/ilias-uihk_authguard AuthGuard
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
