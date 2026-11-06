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
 * Cloudflare Turnstile. The widget script comes from Cloudflare.
 *
 * @see https://developers.cloudflare.com/turnstile/get-started/
 */
class ilAuthGuardProviderTurnstile extends ilAuthGuardExternalProvider
{
    /** @var string */
    public const ID = "turnstile";

    /** @var string POST field the widget fills */
    public const POST_FIELD = "cf-turnstile-response";

    /** @var string Cloudflare does not document the shape of its keys, so only the alphabet is checked */
    private const KEY_PATTERN = "/^[A-Za-z0-9_-]{16,100}$/D";

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
        return ilAuthGuardVerificationResult::REASON_TURNSTILE;
    }

    /**
     * @param ilAuthGuardProviderContext $context
     * @return ilAuthGuardSiteverify
     */
    protected function createVerifier(ilAuthGuardProviderContext $context): ilAuthGuardSiteverify
    {
        return new ilAuthGuardTurnstile($context->settings, $context->logger);
    }

    /**
     * @return string
     */
    protected function getScriptPath(): string
    {
        return "/js/authguard-turnstile.js";
    }

    /**
     * @param string $field
     * @return string
     */
    protected function getKeyPattern(string $field): string
    {
        return self::KEY_PATTERN;
    }
}
