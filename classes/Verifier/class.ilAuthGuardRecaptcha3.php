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
 * Checks the token of a Google reCAPTCHA v3 call with Google: the call
 * must succeed, carry the action of the protected form and score at least
 * the configured threshold.
 *
 * @see https://developers.google.com/recaptcha/docs/v3
 * @see https://developers.google.com/recaptcha/docs/verify
 */
class ilAuthGuardRecaptcha3 extends ilAuthGuardSiteverify
{
    /** @var string */
    public const VERIFY_URL = "https://www.google.com/recaptcha/api/siteverify";

    /**
     * The action name sent with the token of a form. Google allows letters,
     * digits, slashes and underscores only.
     *
     * @param string $form_id
     * @return string
     */
    public static function actionFor(string $form_id): string
    {
        return "authguard_" . (string) preg_replace("/[^A-Za-z0-9_]/", "_", $form_id);
    }

    /**
     * @return string
     */
    protected function getLabel(): string
    {
        return "reCAPTCHA v3";
    }

    /**
     * @return string
     */
    protected function getProviderId(): string
    {
        return ilAuthGuardProviderRecaptcha3::ID;
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

    /**
     * @param array<mixed> $data
     * @param string $form_id
     * @return bool
     */
    protected function judge(array $data, string $form_id): bool
    {
        if (($data["success"] ?? false) !== true) {
            return $this->fail("rejected" . $this->describeErrorCodes($data["error-codes"] ?? []));
        }

        $action = $data["action"] ?? null;
        if (!is_string($action) || !hash_equals(self::actionFor($form_id), $action)) {
            return $this->fail("action_mismatch");
        }

        $score = $data["score"] ?? null;
        if ((!is_int($score) && !is_float($score)) || $score < 0 || $score > 1) {
            return $this->fail("score_missing");
        }

        $threshold = ilAuthGuardProviderRecaptcha3::readThreshold($this->settings);
        if ($score < $threshold) {
            return $this->fail(sprintf("score_below_threshold (%.2f < %.2f)", $score, $threshold));
        }

        return true;
    }
}
