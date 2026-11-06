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
     * @return ilAuthGuardPrivacyFacts
     */
    public function getPrivacyFacts(): ilAuthGuardPrivacyFacts
    {
        return new ilAuthGuardPrivacyFacts(
            name: "hCaptcha",
            service: "the hCaptcha security service",
            purpose: "check that a submission is made by a person and not by an automated program",
            about: "hCaptcha is provided by Intuition Machines, Inc., a company incorporated in "
              . "Delaware, USA (\"hCaptcha\").",
            processing: "When a visitor reaches a page with a protected form, hCaptcha analyses the "
              . "visitor's behaviour automatically, in some cases in the background without "
              . "showing any challenge. It processes data such as the IP address, browser type "
              . "and device type, the time spent on the page and human-verification data such "
              . "as mouse movements, scroll position, keypress events and touch events. The "
              . "data are sent to hCaptcha.",
            controller: "hCaptcha acts as a data processor on our behalf under a data processing "
              . "addendum that includes the EU standard contractual clauses. hCaptcha adheres "
              . "to the EU-U.S. Data Privacy Framework, and the data may be transferred to and "
              . "processed in the United States.",
            consent_subject: "the hCaptcha script and any cookies or similar technologies",
            more_information: "hCaptcha privacy policy, https://www.hcaptcha.com/privacy",
            checks: [
                "The hCaptcha data processing addendum is incorporated in the hCaptcha terms: "
                  . "check that your account accepted those terms, and keep a copy of the addendum.",
                "Check the statements about the EU standard contractual clauses, the EU-U.S. "
                  . "Data Privacy Framework and the transfer to the United States against the "
                  . "current hCaptcha privacy policy (https://www.hcaptcha.com/privacy).",
                "hCaptcha's own sample text also names Art. 6(1)(b) GDPR next to Art. 6(1)(f); "
                  . "this draft uses Art. 6(1)(f) only: confirm with the data protection officer "
                  . "which legal basis applies to this site.",
                "The analysis can run in the background without showing a challenge: keep the "
                  . "sentence that says so in the draft.",
            ]
        );
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
