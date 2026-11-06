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
     * @return ilAuthGuardPrivacyFacts
     */
    public function getPrivacyFacts(): ilAuthGuardPrivacyFacts
    {
        return new ilAuthGuardPrivacyFacts(
            name: "Google reCAPTCHA v3",
            service: "Google reCAPTCHA v3",
            purpose: "tell human visitors from automated programs",
            about: "The service is invisible and scores each visit. [If the reCAPTCHA badge is "
              . "hidden, the page must state that the site is protected by reCAPTCHA, for "
              . "example: \"This site is protected by reCAPTCHA.\"] The service is provided by "
              . "[Google legal entity and country, as named in the Google Cloud contract].",
            processing: "When a visitor reaches a page with a protected form, the service examines "
              . "signals about the visit to assess the risk of automated abuse, and sets the "
              . "cookie _GRECAPTCHA, which Google describes as necessary to provide its risk "
              . "analysis. [Data categories processed by Google: to be completed from the "
              . "Google documentation.]",
            controller: "Since 2 April 2026 Google acts as a data processor on our behalf and we are "
              . "the sole controller; Google commits to comply with the GDPR in its Cloud Data "
              . "Processing Addendum. [Location of the processing and transfers outside the EU: "
              . "to be completed from the Google Cloud terms.]",
            consent_subject: "the reCAPTCHA script and the cookie",
            more_information: "[link to the Google privacy information for reCAPTCHA]",
            checks: [
                "Conclude or accept the Google Cloud Data Processing Addendum for the Google "
                  . "account that issued the reCAPTCHA keys.",
                "Replace [Google legal entity and country, as named in the Google Cloud "
                  . "contract] with the entity and country named in your Google Cloud contract.",
                "Replace [Data categories processed by Google: to be completed from the Google "
                  . "documentation] with the data categories listed in Google's reCAPTCHA "
                  . "documentation.",
                "Replace [Location of the processing and transfers outside the EU: to be "
                  . "completed from the Google Cloud terms] with the location and the transfer "
                  . "safeguards stated in the Google Cloud terms.",
                "Replace [link to the Google privacy information for reCAPTCHA] with the link "
                  . "you use for Google's reCAPTCHA privacy information.",
                "Confirm that Google still acts as processor and that you are the sole "
                  . "controller (stated by Google from 2 April 2026): "
                  . "https://docs.cloud.google.com/recaptcha/docs/faq",
                "The service sets the necessary cookie _GRECAPTCHA: list it in the cookie "
                  . "information of this site if you keep such a list.",
                "If the reCAPTCHA badge is hidden, show the sentence \"This site is protected by "
                  . "reCAPTCHA.\" on every page with a protected form, and resolve the bracketed "
                  . "badge note in the draft.",
                "Decide the score threshold in the AuthGuard settings together with the people "
                  . "who handle the rejected submits: a visitor below the threshold is rejected "
                  . "without a second chance.",
            ]
        );
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
