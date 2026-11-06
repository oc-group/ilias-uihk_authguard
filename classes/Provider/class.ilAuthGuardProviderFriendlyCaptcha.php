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
 * Friendly Captcha v2. The widget (npm package @friendlycaptcha/sdk) is
 * served from the plugin; the visitor's browser still fetches the puzzle
 * from, and the server verifies the response with, Friendly Captcha, at
 * the global or the EU endpoint.
 *
 * @see https://developer.friendlycaptcha.com/docs/v2/sdk/configuration
 */
class ilAuthGuardProviderFriendlyCaptcha extends ilAuthGuardExternalProvider
{
    /** @var string */
    public const ID = "friendlycaptcha";

    /** @var string POST field the widget fills */
    public const POST_FIELD = "frc-captcha-response";

    /** @var string Friendly Captcha does not document the shape of its keys, so only the alphabet is checked */
    private const SITE_KEY_PATTERN = "/^[A-Za-z0-9_-]{8,100}$/D";

    /** @var string */
    private const API_KEY_PATTERN = "/^[A-Za-z0-9_.~-]{16,200}$/D";

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
        return ilAuthGuardVerificationResult::REASON_FRIENDLY_CAPTCHA;
    }

    /**
     * @return ilAuthGuardPrivacyFacts
     */
    public function getPrivacyFacts(): ilAuthGuardPrivacyFacts
    {
        return new ilAuthGuardPrivacyFacts(
            name: "Friendly Captcha",
            service: "Friendly Captcha",
            purpose: "tell human visitors from automated programs",
            about: "Friendly Captcha is provided by Friendly Captcha GmbH, Germany.",
            processing: "When a visitor reaches a page with a protected form, the visitor's browser "
              . "solves a small puzzle in the background and transfers connection data, "
              . "environment data, interaction data and functional data to Friendly Captcha. "
              . "The data are used only to identify and handle potential bots and risks. "
              . "Friendly Captcha states that IP addresses are anonymised with a one-way hash "
              . "function before they are stored, and that it sets no HTTP cookies.",
            controller: "Friendly Captcha acts as a data processor on our behalf. Friendly Captcha "
              . "states that all data stays in the European Union and that it uses EU "
              . "sub-processors only. [If the EU endpoint is selected in the AuthGuard "
              . "settings, requests are processed within the EU; otherwise confirm the "
              . "processing location with the vendor.] [Data processing agreement: to be "
              . "concluded or confirmed.]",
            consent_subject: "the Friendly Captcha script and any similar technologies",
            more_information: "https://friendlycaptcha.com/legal/privacy-end-users/",
            checks: [
                "Request the data processing agreement from Friendly Captcha, conclude it, and "
                  . "then remove the bracketed note about the agreement from the draft.",
                "State that the processing stays within the EU only if the EU endpoint is "
                  . "selected in the AuthGuard settings and enabled for the site key in the "
                  . "Friendly Captcha dashboard (Advanced or Enterprise plan); otherwise delete the "
                  . "bracketed EU sentence and confirm the processing location with the vendor.",
                "Check the vendor's statements about EU sub-processors, hashed IP addresses and "
                  . "the absence of HTTP cookies against https://friendlycaptcha.com/legal/gdpr/",
            ]
        );
    }

    /**
     * @param ilAuthGuardProviderContext $context
     * @return ilAuthGuardSiteverify
     */
    protected function createVerifier(ilAuthGuardProviderContext $context): ilAuthGuardSiteverify
    {
        return new ilAuthGuardFriendlyCaptcha($context->settings, $context->logger);
    }

    /**
     * @return string
     */
    protected function getScriptPath(): string
    {
        return "/js/authguard-friendlycaptcha.js";
    }

    /**
     * @param string $field
     * @return string
     */
    protected function getKeyPattern(string $field): string
    {
        return $field === "site_key" ? self::SITE_KEY_PATTERN : self::API_KEY_PATTERN;
    }

    /**
     * @return string
     */
    protected function getSecretFieldName(): string
    {
        return "api_key";
    }

    /**
     * @return string
     */
    protected function getSecretLabelKey(): string
    {
        return "cfg_api_key";
    }

    /**
     * @return ilAuthGuardProviderField[]
     */
    protected function getExtraFields(): array
    {
        return [
            new ilAuthGuardProviderField(
                "endpoint",
                ilAuthGuardProviderField::TYPE_SELECT,
                "cfg_endpoint",
                "cfg_err_endpoint",
                "cfg_endpoint_info",
                [
                    ilAuthGuardFriendlyCaptcha::ENDPOINT_GLOBAL => "cfg_endpoint_global",
                    ilAuthGuardFriendlyCaptcha::ENDPOINT_EU => "cfg_endpoint_eu",
                ],
                ilAuthGuardFriendlyCaptcha::ENDPOINT_GLOBAL
            ),
        ];
    }

    /**
     * @param array<string, string> $values
     * @return array<string, string>
     */
    protected function validateExtra(array $values): array
    {
        if (!array_key_exists($values["endpoint"] ?? "", ilAuthGuardFriendlyCaptcha::VERIFY_URLS)) {
            return ["endpoint" => "cfg_err_endpoint"];
        }

        return [];
    }

    /**
     * @return string[]
     */
    protected function getExtraBlockVariables(): array
    {
        return ["FRIENDLYCAPTCHA_ENDPOINT"];
    }

    /**
     * @param ilAuthGuardProviderContext $context
     * @return array<string, string>
     */
    protected function getExtraRenderVariables(ilAuthGuardProviderContext $context): array
    {
        $stored = $context->settings->getProviderValue(
            self::ID,
            "endpoint",
            ilAuthGuardFriendlyCaptcha::ENDPOINT_GLOBAL
        );

        return ["FRIENDLYCAPTCHA_ENDPOINT" => ilAuthGuardFriendlyCaptcha::normalizeEndpoint($stored)];
    }
}
