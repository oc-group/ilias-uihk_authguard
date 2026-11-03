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
 * Checks the answer of a Google reCAPTCHA v2 widget with Google. Fails
 * closed: an unreachable service, a timeout, an unreadable reply or a
 * missing key all count as a failed check. Every failure is logged at
 * warning level with its reason and nothing else: no visitor data, no
 * key, no answer.
 */
class ilAuthGuardRecaptcha
{
    /** @var string */
    public const VERIFY_URL = "https://www.google.com/recaptcha/api/siteverify";

    /** @var int seconds the whole request may take */
    public const TIMEOUT_SECONDS = 5;

    /** @var int seconds the connection may take to open */
    public const CONNECT_TIMEOUT_SECONDS = 3;

    /** @var int longest accepted answer, in characters */
    public const MAX_RESPONSE_LENGTH = 8192;

    /** @var int most error codes copied into the log line */
    private const MAX_LOGGED_ERROR_CODES = 5;

    /** @var ilAuthGuardSettings */
    private ilAuthGuardSettings $settings;

    /** @var \ilLogger|null fetched on first use */
    private ?\ilLogger $logger;

    /**
     * @param ilAuthGuardSettings $settings
     * @param \ilLogger|null $logger
     * @return void
     */
    public function __construct(ilAuthGuardSettings $settings, ?\ilLogger $logger = null)
    {
        $this->settings = $settings;
        $this->logger = $logger;
    }

    /**
     * @param string $response the value of the g-recaptcha-response field
     * @return bool true only when Google confirms the answer
     */
    public function verify(string $response): bool
    {
        if ($response === "" || strlen($response) > self::MAX_RESPONSE_LENGTH) {
            return $this->fail("response_shape");
        }

        try {
            $secret = $this->settings->getRecaptchaSecretKey();
        } catch (\Throwable $e) {
            return $this->fail("secret_unavailable");
        }

        if ($secret === "") {
            return $this->fail("secret_missing");
        }

        try {
            $reply = $this->post(self::VERIFY_URL, [
                "secret" => $secret,
                "response" => $response,
            ]);
        } catch (\Throwable $e) {
            return $this->fail("service_unreachable: " . $e->getMessage());
        }

        $data = json_decode($reply, true);
        if (!is_array($data)) {
            return $this->fail("reply_unreadable");
        }

        if (($data["success"] ?? false) === true) {
            return true;
        }

        return $this->fail("rejected" . $this->describeErrorCodes($data));
    }

    /**
     * Sends the POST request, through the proxy ILIAS is configured with.
     *
     * @param string $url
     * @param array<string, string> $fields
     * @throws \Throwable on a transport failure or a status other than 200
     * @return string the reply body
     */
    protected function post(string $url, array $fields): string
    {
        $curl = new \ilCurlConnection($url);
        $curl->init();
        $curl->setOpt(CURLOPT_POST, true);
        $curl->setOpt(CURLOPT_POSTFIELDS, http_build_query($fields, "", "&"));
        $curl->setOpt(CURLOPT_RETURNTRANSFER, true);
        $curl->setOpt(CURLOPT_TIMEOUT, self::TIMEOUT_SECONDS);
        $curl->setOpt(CURLOPT_CONNECTTIMEOUT, self::CONNECT_TIMEOUT_SECONDS);
        $curl->setOpt(CURLOPT_FOLLOWLOCATION, false);
        $curl->setOpt(CURLOPT_SSL_VERIFYPEER, true);
        $curl->setOpt(CURLOPT_SSL_VERIFYHOST, 2);

        try {
            $body = $curl->exec();
            $status = (int) $curl->getInfo(CURLINFO_RESPONSE_CODE);
        } finally {
            $curl->close();
        }

        if ($status !== 200) {
            throw new \RuntimeException("HTTP status " . $status);
        }

        return is_string($body) ? $body : "";
    }

    /**
     * The error codes Google names, as a short suffix for the log line.
     * Only codes of the documented shape are copied.
     *
     * @param array<mixed> $data
     * @return string
     */
    private function describeErrorCodes(array $data): string
    {
        $codes = [];
        $listed = $data["error-codes"] ?? [];

        if (is_array($listed)) {
            foreach ($listed as $code) {
                if (is_string($code) && preg_match("/^[a-z0-9-]{1,40}$/D", $code) === 1) {
                    $codes[] = $code;
                }
            }
        }

        $codes = array_slice($codes, 0, self::MAX_LOGGED_ERROR_CODES);

        return $codes === [] ? "" : ": " . implode(", ", $codes);
    }

    /**
     * @param string $reason
     * @return false
     */
    private function fail(string $reason): bool
    {
        $this->getLogger()->warning("AuthGuard: reCAPTCHA verification failed (reason: " . $reason . ")");

        return false;
    }

    /**
     * @return \ilLogger
     */
    private function getLogger(): \ilLogger
    {
        global $DIC;

        if ($this->logger === null) {
            $this->logger = $DIC->logger()->root();
        }

        return $this->logger;
    }
}
