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
 * Checks the answer of a Google reCAPTCHA v2 widget with Google.
 *
 * @see https://developers.google.com/recaptcha/docs/verify
 */
class ilAuthGuardRecaptcha extends ilAuthGuardSiteverify
{
    /** @var string */
    public const VERIFY_URL = "https://www.google.com/recaptcha/api/siteverify";

    /**
     * @return string
     */
    protected function getLabel(): string
    {
        return "reCAPTCHA";
    }

    /**
     * @return string
     */
    protected function getProviderId(): string
    {
        return ilAuthGuardProviderRecaptcha::ID;
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
