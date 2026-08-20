# Security Policy

## Reporting a vulnerability

E-mail **plugins@oc-group.eu** -- the address listed as `$responsible_mail` in `plugin.php`.

**Do not open a public issue.** This plugin guards the account-registration form of every
installation running it, so a public report is an exploitation guide until each of them has updated.

Include, as far as you can:

- the plugin version (`$version` in `plugin.php`) and the ILIAS version
- what an attacker can achieve
- the steps to reproduce it

We confirm receipt, tell you whether we consider the report a vulnerability and why, and keep you
informed until a fix is released. Say in your report if you want to be credited in the release
notes; we will not name you otherwise.

## Scope

Please report:

- a bot completing a registration while the plugin is active
- any bypass that costs an attacker no real effort
- a legitimate visitor being blocked with no way through
- injection, disclosure or resource exhaustion in the plugin's own endpoints

Known limits, not vulnerabilities:

- the image CAPTCHA renders distorted text, which commodity OCR reads and solving services clear
  cheaply
- the submit-timing check is defeated by inserting a delay
- no check here proves a visitor is human: they raise the cost of untargeted, high-volume
  automation, which is the threat they were built for
