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
     * @return ilAuthGuardPrivacyFacts
     */
    public function getPrivacyFacts(): ilAuthGuardPrivacyFacts
    {
        return new ilAuthGuardPrivacyFacts(
            name: "Cloudflare Turnstile",
            service: "Cloudflare Turnstile",
            purpose: "tell human visitors from automated programs",
            about: "Turnstile is provided by Cloudflare, Inc. [country of the vendor, to be "
              . "completed from the vendor's policy].",
            processing: "When a visitor reaches a page with a protected form, Turnstile processes "
              . "client-side signals such as the client IP address, the TLS fingerprint, the "
              . "User-Agent header and the sitekey with its associated origin, and sends them "
              . "to Cloudflare.",
            controller: "Cloudflare acts as a data processor on our behalf for the signals it processes "
              . "to provide the Turnstile service, under the Cloudflare data processing "
              . "addendum (https://www.cloudflare.com/cloudflare-customer-dpa/). For the "
              . "signals it processes to improve its bot detection, Cloudflare acts as a "
              . "controller. Transfers outside the European Economic Area are governed by the "
              . "safeguards of that addendum, which provides for the EU standard contractual "
              . "clauses and the Data Privacy Framework. [Location of the processing: to be "
              . "completed.]",
            consent_subject: "the Turnstile script and any cookies or similar technologies",
            more_information: "https://www.cloudflare.com/en-gb/turnstile-privacy-policy/ and "
              . "https://www.cloudflare.com/en-gb/cookie-policy/",
            checks: [
                "Accept the Cloudflare Customer DPA "
                  . "(https://www.cloudflare.com/cloudflare-customer-dpa/) for the Cloudflare "
                  . "account that issued the Turnstile keys.",
                "Replace [country of the vendor, to be completed from the vendor's policy] with "
                  . "the country of Cloudflare, Inc. as stated by the vendor.",
                "Replace [Location of the processing: to be completed.] with the processing "
                  . "location stated by Cloudflare.",
                "Check the safeguards named in the draft (EU standard contractual clauses, Data "
                  . "Privacy Framework) against the version of the DPA you accepted.",
                "Cloudflare is a controller, not a processor, for the signals it uses to "
                  . "improve bot detection: make sure the privacy policy of this site says so and "
                  . "that you accept it.",
                "Check the Cloudflare Cookie Policy "
                  . "(https://www.cloudflare.com/en-gb/cookie-policy/) for the cookies Turnstile "
                  . "uses and list them if you keep a cookie list.",
            ]
        );
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
