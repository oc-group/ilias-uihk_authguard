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
 * Google reCAPTCHA v3: invisible, score based. The visitor sees no widget
 * but Google's badge; a submit scoring below the threshold is refused.
 * Needs its own pair of keys, v2 and v3 keys are not interchangeable.
 *
 * @see https://developers.google.com/recaptcha/docs/v3
 */
class ilAuthGuardProviderRecaptcha3 extends ilAuthGuardExternalProvider
{
    /** @var string */
    public const ID = "recaptcha3";

    /** @var string POST field of the hidden input the script fills with the token */
    public const POST_FIELD = "authguard_recaptcha3";

    /** @var float score from which a submit passes, unless the administrator sets another */
    public const DEFAULT_THRESHOLD = 0.5;

    /** @var string a number from 0 to 1 with at most two decimals */
    private const THRESHOLD_PATTERN = "/^(?:0(?:\.[0-9]{1,2})?|1(?:\.0{1,2})?)$/D";

    /**
     * The threshold in force: the stored one, or the default when none is
     * stored or the stored value is not a score.
     *
     * @param ilAuthGuardSettings $settings
     * @return float
     */
    public static function readThreshold(ilAuthGuardSettings $settings): float
    {
        $stored = $settings->getProviderValue(self::ID, "threshold");

        return preg_match(self::THRESHOLD_PATTERN, $stored) === 1 ? (float) $stored : self::DEFAULT_THRESHOLD;
    }

    /**
     * @return string
     */
    public function getId(): string
    {
        return self::ID;
    }

    /**
     * @return string
     */
    public function getPostField(): string
    {
        return self::POST_FIELD;
    }

    /**
     * @return string
     */
    public function getFailureReason(): string
    {
        return ilAuthGuardVerificationResult::REASON_RECAPTCHA3;
    }

    /**
     * @param ilAuthGuardProviderContext $context
     * @return ilAuthGuardSiteverify
     */
    protected function createVerifier(ilAuthGuardProviderContext $context): ilAuthGuardSiteverify
    {
        return new ilAuthGuardRecaptcha3($context->settings, $context->logger);
    }

    /**
     * @return string
     */
    protected function getScriptPath(): string
    {
        return "/js/authguard-recaptcha3.js";
    }

    /**
     * @param string $field
     * @return string
     */
    protected function getKeyPattern(string $field): string
    {
        return ilAuthGuardProviderRecaptcha::GOOGLE_KEY_PATTERN;
    }

    /**
     * @return string
     */
    protected function getSiteKeyErrorKey(): string
    {
        return "cfg_err_site_key";
    }

    /**
     * @return string
     */
    protected function getSecretErrorKey(): string
    {
        return "cfg_err_secret_key";
    }

    /**
     * @return ilAuthGuardProviderField[]
     */
    protected function getExtraFields(): array
    {
        return [
            new ilAuthGuardProviderField(
                "threshold",
                ilAuthGuardProviderField::TYPE_TEXT,
                "cfg_threshold",
                "cfg_err_threshold",
                "cfg_threshold_info",
                [],
                (string) self::DEFAULT_THRESHOLD,
                4
            ),
        ];
    }

    /**
     * @param array<string, string> $values
     * @return array<string, string>
     */
    protected function validateExtra(array $values): array
    {
        if (preg_match(self::THRESHOLD_PATTERN, $values["threshold"] ?? "") !== 1) {
            return ["threshold" => "cfg_err_threshold"];
        }

        return [];
    }

    /**
     * @return string[]
     */
    protected function getExtraBlockVariables(): array
    {
        return ["RECAPTCHA3_ACTION", "RECAPTCHA3_FIELD"];
    }

    /**
     * @param ilAuthGuardProviderContext $context
     * @return array<string, string>
     */
    protected function getExtraRenderVariables(ilAuthGuardProviderContext $context): array
    {
        return [
            "RECAPTCHA3_ACTION" => ilAuthGuardRecaptcha3::actionFor($context->form_id),
            "RECAPTCHA3_FIELD" => self::POST_FIELD,
        ];
    }
}
