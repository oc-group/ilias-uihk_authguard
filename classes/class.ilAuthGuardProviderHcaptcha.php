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
 * hCaptcha. The widget script comes from hCaptcha.
 *
 * @see https://docs.hcaptcha.com/
 */
class ilAuthGuardProviderHcaptcha extends ilAuthGuardExternalProvider
{
    /** @var string */
    public const ID = "hcaptcha";

    /** @var string POST field the widget fills */
    public const POST_FIELD = "h-captcha-response";

    /** @var string a site key is a UUID */
    private const SITE_KEY_PATTERN = "/^[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}$/D";

    /** @var string hCaptcha does not document the shape of a secret, so only the alphabet is checked */
    private const SECRET_PATTERN = "/^[A-Za-z0-9_-]{16,100}$/D";

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
        return ilAuthGuardVerificationResult::REASON_HCAPTCHA;
    }

    /**
     * @param ilAuthGuardProviderContext $context
     * @return ilAuthGuardSiteverify
     */
    protected function createVerifier(ilAuthGuardProviderContext $context): ilAuthGuardSiteverify
    {
        return new ilAuthGuardHcaptcha($context->settings, $context->logger);
    }

    /**
     * @return string
     */
    protected function getScriptPath(): string
    {
        return "/js/authguard-hcaptcha.js";
    }

    /**
     * @param string $field
     * @return string
     */
    protected function getKeyPattern(string $field): string
    {
        return $field === "site_key" ? self::SITE_KEY_PATTERN : self::SECRET_PATTERN;
    }
}
