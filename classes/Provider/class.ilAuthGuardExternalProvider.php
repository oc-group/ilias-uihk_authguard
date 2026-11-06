<?php

/**
 * This file is part of AuthGuard Plugin for ILIAS,
 * developed by OC Open Consulting to block automated self-registration
 * submissions with a local image CAPTCHA.
 *
 * @author Vincenzo Padula <vincenzo@oc-group.eu>
 * @copyright 2026 OC Open Consulting SB Srl
 * @license http://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */

declare(strict_types=1);

/**
 * Base of the providers whose widget comes from a third party: a site key
 * and a secret, a widget drawn by a script of the plugin, and a siteverify
 * call on the server. A subclass names itself, its keys, its script and
 * its verifier; one with more settings adds them through the extra hooks.
 */
abstract class ilAuthGuardExternalProvider implements ilAuthGuardChallengeProvider
{
    /** @var ilAuthGuardSiteverify|null replaces the verifier (tests) */
    private ?ilAuthGuardSiteverify $verifier;

    /**
     * @param ilAuthGuardSiteverify|null $verifier replaces the verifier (tests)
     * @return void
     */
    public function __construct(?ilAuthGuardSiteverify $verifier = null)
    {
        $this->verifier = $verifier;
    }

    /**
     * @return bool
     */
    public function isExternal(): bool
    {
        return true;
    }

    /**
     * @return ilAuthGuardPrivacyFacts an external provider always has them
     */
    abstract public function getPrivacyFacts(): ilAuthGuardPrivacyFacts;

    /**
     * @param ilAuthGuardProviderContext $context
     * @return ilAuthGuardSiteverify
     */
    abstract protected function createVerifier(ilAuthGuardProviderContext $context): ilAuthGuardSiteverify;

    /**
     * @return string script path, with a leading slash, relative to the plugin
     */
    abstract protected function getScriptPath(): string;

    /**
     * @param string $field "site_key" or the name of the secret
     * @return string regular expression a value of that field has to match
     */
    abstract protected function getKeyPattern(string $field): string;

    /**
     * @return string lang key of the message shown for a malformed site key
     */
    protected function getSiteKeyErrorKey(): string
    {
        return "cfg_err_" . $this->getId() . "_site_key";
    }

    /**
     * @return string lang key of the error for a malformed or missing secret
     */
    protected function getSecretErrorKey(): string
    {
        return "cfg_err_" . $this->getId() . "_" . $this->getSecretFieldName();
    }

    /**
     * @return string
     */
    protected function getSecretFieldName(): string
    {
        return "secret_key";
    }

    /**
     * @return string lang key of the label of the secret
     */
    protected function getSecretLabelKey(): string
    {
        return "cfg_secret_key";
    }

    /**
     * Settings after the site key and the secret.
     *
     * @return ilAuthGuardProviderField[]
     */
    protected function getExtraFields(): array
    {
        return [];
    }

    /**
     * @param array<string, string> $values
     * @return array<string, string> lang key by field name
     */
    protected function validateExtra(array $values): array
    {
        return [];
    }

    /**
     * @return string[] block variables besides the site key and the script
     */
    protected function getExtraBlockVariables(): array
    {
        return [];
    }

    /**
     * @param ilAuthGuardProviderContext $context
     * @return array<string, string> values by extra block variable name
     */
    protected function getExtraRenderVariables(ilAuthGuardProviderContext $context): array
    {
        return [];
    }

    /**
     * @return string
     */
    protected function getVariablePrefix(): string
    {
        return strtoupper($this->getId());
    }

    /**
     * @return string[]
     */
    public function getBlockVariables(): array
    {
        $prefix = $this->getVariablePrefix();

        return array_merge([$prefix . "_SITE_KEY", $prefix . "_SCRIPT_URL"], $this->getExtraBlockVariables());
    }

    /**
     * @return ilAuthGuardProviderField[]
     */
    public function getSettingsFields(): array
    {
        return array_merge([
            new ilAuthGuardProviderField(
                "site_key",
                ilAuthGuardProviderField::TYPE_TEXT,
                "cfg_site_key",
                $this->getSiteKeyErrorKey()
            ),
            new ilAuthGuardProviderField(
                $this->getSecretFieldName(),
                ilAuthGuardProviderField::TYPE_SECRET,
                $this->getSecretLabelKey(),
                $this->getSecretErrorKey()
            ),
        ], $this->getExtraFields());
    }

    /**
     * @param ilAuthGuardSettings $settings
     * @return bool
     */
    public function isConfigured(ilAuthGuardSettings $settings): bool
    {
        return $settings->getProviderValue($this->getId(), "site_key") !== ""
            && $settings->hasProviderSecret($this->getId(), $this->getSecretFieldName());
    }

    /**
     * The site key must have the shape the vendor issues; the secret too,
     * and it may be left empty only when one is already stored.
     *
     * @param array<string, string> $values
     * @param array<string, bool> $secrets_stored
     * @return array<string, string>
     */
    public function validate(array $values, array $secrets_stored): array
    {
        $errors = [];
        $secret_name = $this->getSecretFieldName();
        $site_key = $values["site_key"] ?? "";
        $secret = $values[$secret_name] ?? "";

        if (preg_match($this->getKeyPattern("site_key"), $site_key) !== 1) {
            $errors["site_key"] = $this->getSiteKeyErrorKey();
        }

        if ($secret === "") {
            if (!($secrets_stored[$secret_name] ?? false)) {
                $errors[$secret_name] = $this->getSecretErrorKey();
            }
        } elseif (preg_match($this->getKeyPattern($secret_name), $secret) !== 1) {
            $errors[$secret_name] = $this->getSecretErrorKey();
        }

        return $errors + $this->validateExtra($values);
    }

    /**
     * @param ilAuthGuardProviderContext $context
     * @return void
     */
    public function prepare(ilAuthGuardProviderContext $context): void
    {
    }

    /**
     * @param ilAuthGuardProviderContext $context
     * @return array<string, string>
     */
    public function getRenderVariables(ilAuthGuardProviderContext $context): array
    {
        $prefix = $this->getVariablePrefix();

        return [
            $prefix . "_SITE_KEY" => $context->settings->getProviderValue($this->getId(), "site_key"),
            $prefix . "_SCRIPT_URL" => $context->getAssetUrl($this->getScriptPath()),
        ] + $this->getExtraRenderVariables($context);
    }

    /**
     * @param string $answer
     * @param ilAuthGuardProviderContext $context
     * @return string
     */
    public function check(string $answer, ilAuthGuardProviderContext $context): string
    {
        $verifier = $this->verifier ?? $this->createVerifier($context);

        if ($verifier->verify($answer, $context->form_id)) {
            return self::OUTCOME_PASSED;
        }

        return $verifier->wasUnreachable() ? self::OUTCOME_UNREACHABLE : self::OUTCOME_REJECTED;
    }
}
