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
 * Checks the token of a Cloudflare Turnstile widget with Cloudflare.
 *
 * @see https://developers.cloudflare.com/turnstile/get-started/
 */
class ilAuthGuardTurnstile extends ilAuthGuardSiteverify
{
    /** @var string */
    public const VERIFY_URL = "https://challenges.cloudflare.com/turnstile/v0/siteverify";

    /** @var int longest token Cloudflare accepts */
    public const MAX_RESPONSE_LENGTH = 2048;

    /**
     * @return string
     */
    protected function getLabel(): string
    {
        return "Turnstile";
    }

    /**
     * @return string
     */
    protected function getProviderId(): string
    {
        return ilAuthGuardProviderTurnstile::ID;
    }

    /**
     * @return string
     */
    protected function getVerifyUrl(): string
    {
        return self::VERIFY_URL;
    }

    /**
     * @param string $secret
     * @param string $response
     * @return array<string, string>
     */
    protected function buildFields(string $secret, string $response): array
    {
        return ["secret" => $secret, "response" => $response];
    }
}
