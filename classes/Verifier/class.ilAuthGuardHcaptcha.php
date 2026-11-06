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
 * Checks the token of an hCaptcha widget with hCaptcha. The site key is
 * sent along, so a token issued for another site is refused.
 *
 * @see https://docs.hcaptcha.com/
 */
class ilAuthGuardHcaptcha extends ilAuthGuardSiteverify
{
    /** @var string */
    public const VERIFY_URL = "https://api.hcaptcha.com/siteverify";

    /** @var int hCaptcha tokens are longer than reCAPTCHA ones */
    public const MAX_RESPONSE_LENGTH = 16384;

    /**
     * @return string
     */
    protected function getLabel(): string
    {
        return "hCaptcha";
    }

    /**
     * @return string
     */
    protected function getProviderId(): string
    {
        return ilAuthGuardProviderHcaptcha::ID;
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
        $fields = ["secret" => $secret, "response" => $response];

        $site_key = $this->settings->getProviderValue($this->getProviderId(), "site_key");
        if ($site_key !== "") {
            $fields["sitekey"] = $site_key;
        }

        return $fields;
    }
}
