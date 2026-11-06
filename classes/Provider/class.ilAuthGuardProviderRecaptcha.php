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
     * @return ilAuthGuardPrivacyFacts
     */
    public function getPrivacyFacts(): ilAuthGuardPrivacyFacts
    {
        return new ilAuthGuardPrivacyFacts(
            name: "Google reCAPTCHA v2",
            service: "Google reCAPTCHA v2",
            purpose: "tell human visitors from automated programs",
            about: "The visitor ticks a checkbox. The service is provided by [Google legal entity "
              . "and country, as named in the Google Cloud contract].",
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
            ]
        );
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
