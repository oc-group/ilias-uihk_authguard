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
 * Checks the response of a Friendly Captcha v2 widget with Friendly
 * Captcha, at the global or the EU endpoint the administrator chose. The
 * API key travels in the X-API-Key header, the response and the site key
 * in the body.
 *
 * Friendly Captcha advises accepting the submit when its service cannot be
 * reached. AuthGuard rejects it unless the administrator chose to accept
 * such submits.
 *
 * @see https://developer.friendlycaptcha.com/docs/v2/api/siteverify
 * @see https://developer.friendlycaptcha.com/docs/v2/guides/eu-endpoint
 */
class ilAuthGuardFriendlyCaptcha extends ilAuthGuardSiteverify
{
    /** @var string */
    public const ENDPOINT_GLOBAL = "global";

    /** @var string */
    public const ENDPOINT_EU = "eu";

    /** @var array<string, string> siteverify URL by endpoint */
    public const VERIFY_URLS = [
        self::ENDPOINT_GLOBAL => "https://global.frcapi.com/api/v2/captcha/siteverify",
        self::ENDPOINT_EU => "https://eu.frcapi.com/api/v2/captcha/siteverify",
    ];

    /** @var int largest response Friendly Captcha accepts, 16 KB */
    public const MAX_RESPONSE_LENGTH = 16384;

    /**
     * @param string $stored
     * @return string a key of VERIFY_URLS, the global one for any other value
     */
    public static function normalizeEndpoint(string $stored): string
    {
        return array_key_exists($stored, self::VERIFY_URLS) ? $stored : self::ENDPOINT_GLOBAL;
    }

    /**
     * @return string
     */
    protected function getLabel(): string
    {
        return "Friendly Captcha";
    }

    /**
     * @return string
     */
    protected function getProviderId(): string
    {
        return ilAuthGuardProviderFriendlyCaptcha::ID;
    }

    /**
     * @return string
     */
    protected function getSecretField(): string
    {
        return "api_key";
    }

    /**
     * @return string
     */
    protected function getVerifyUrl(): string
    {
        $endpoint = self::normalizeEndpoint(
            $this->settings->getProviderValue($this->getProviderId(), "endpoint", self::ENDPOINT_GLOBAL)
        );

        return self::VERIFY_URLS[$endpoint];
    }

    /**
     * @param string $secret
     * @param string $response
     * @return array<string, string>
     */
    protected function buildFields(string $secret, string $response): array
    {
        return [
            "response" => $response,
            "sitekey" => $this->settings->getProviderValue($this->getProviderId(), "site_key"),
        ];
    }

    /**
     * @return string[]
     */
    protected function getRequestHeaders(): array
    {
        return ["X-API-Key: " . $this->secret];
    }

    /**
     * @param array<mixed> $data
     * @param string $form_id
     * @return bool
     */
    protected function judge(array $data, string $form_id): bool
    {
        if (($data["success"] ?? false) === true) {
            return true;
        }

        $error = $data["error"] ?? null;
        $code = is_array($error) ? ($error["error_code"] ?? null) : null;

        return $this->fail("rejected" . $this->describeErrorCodes([$code]));
    }
}
