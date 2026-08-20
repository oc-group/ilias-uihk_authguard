# AuthGuard

Blocks automated (bot) submissions of the ILIAS self-registration form with a locally generated
image CAPTCHA. ILIAS core shipped a Securimage-based CAPTCHA on self-registration through ILIAS 7;
it was removed in ILIAS 8. This plugin reimplements the protection as a `uihk` plugin.

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
