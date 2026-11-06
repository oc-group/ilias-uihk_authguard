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
 * Google reCAPTCHA v2, the checkbox. The widget script comes from Google.
 *
 * @see https://developers.google.com/recaptcha/docs/display
 */
class ilAuthGuardProviderRecaptcha extends ilAuthGuardExternalProvider
{
    /** @var string */
    public const ID = "recaptcha";

    /** @var string shape of a Google site key and of a Google secret key */
    public const GOOGLE_KEY_PATTERN = "/^[A-Za-z0-9_-]{20,100}$/D";

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
        return ilAuthGuardFormProtection::FIELD_RECAPTCHA;
    }

    /**
     * @return string
     */
    public function getFailureReason(): string
    {
        return ilAuthGuardVerificationResult::REASON_RECAPTCHA;
    }

    /**
     * @param ilAuthGuardProviderContext $context
     * @return ilAuthGuardSiteverify
     */
    protected function createVerifier(ilAuthGuardProviderContext $context): ilAuthGuardSiteverify
    {
        return new ilAuthGuardRecaptcha($context->settings, $context->logger);
    }

    /**
     * @return string
     */
    protected function getScriptPath(): string
    {
        return "/js/authguard-recaptcha.js";
    }

    /**
     * @param string $field
     * @return string
     */
    protected function getKeyPattern(string $field): string
    {
        return self::GOOGLE_KEY_PATTERN;
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
}
