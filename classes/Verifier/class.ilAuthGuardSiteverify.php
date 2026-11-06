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
 * Base of the checks that ask a vendor's siteverify endpoint whether a
 * widget answer is genuine. Fails closed: an unreachable service, a
 * timeout, an unreadable reply or a missing key all count as a failed
 * check. Every failure is logged at warning level with its reason and
 * nothing else: no visitor data, no key, no answer.
 *
 * A subclass names its vendor, its endpoint and the request fields, and
 * judges the decoded reply. The transport is one method, so tests replace
 * only that.
 */
abstract class ilAuthGuardSiteverify
{
    /** @var int seconds the whole request may take */
    public const TIMEOUT_SECONDS = 5;

    /** @var int seconds the connection may take to open */
    public const CONNECT_TIMEOUT_SECONDS = 3;

    /** @var int longest accepted answer, in characters */
    public const MAX_RESPONSE_LENGTH = 8192;

    /** @var int most error codes copied into the log line */
    private const MAX_LOGGED_ERROR_CODES = 5;

    /** @var ilAuthGuardSettings */
    protected ilAuthGuardSettings $settings;

    /** @var string the secret of the request in progress, empty between requests */
    protected string $secret = "";

    /** @var bool whether the last verify() failed because the vendor was not reached */
    private bool $unreachable = false;

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
     * Whether the last verify() failed because the vendor could not be
     * asked, not because it refused the answer. Only a transport failure, a
     * 5xx status or an unreadable reply count: a well-formed refusal never
     * does, and neither does a 4xx status, which points at a wrong key
     * on our side.
     *
     * @return bool
     */
    public function wasUnreachable(): bool
    {
        return $this->unreachable;
    }

    /**
     * @param string $response the answer the widget put into the form
     * @param string $form_id the protected form, for checks bound to it
     * @return bool true only when the vendor confirms the answer
     */
    public function verify(string $response, string $form_id = ""): bool
    {
        $this->unreachable = false;

        if ($response === "" || strlen($response) > static::MAX_RESPONSE_LENGTH) {
            return $this->fail("response_shape");
        }

        try {
            $secret = $this->settings->getProviderSecret($this->getProviderId(), $this->getSecretField());
        } catch (\Throwable $e) {
            return $this->fail("secret_unavailable");
        }

        if ($secret === "") {
            return $this->fail("secret_missing");
        }

        $this->secret = $secret;
        try {
            $reply = $this->post($this->getVerifyUrl(), $this->buildFields($secret, $response));
        } catch (\UnexpectedValueException $e) {
            return $this->fail("unexpected_status: " . $e->getMessage());
        } catch (\Throwable $e) {
            return $this->failUnreachable("service_unreachable: " . $e->getMessage());
        } finally {
            $this->secret = "";
        }

        $data = json_decode($reply, true);
        if (!is_array($data)) {
            return $this->failUnreachable("reply_unreadable");
        }

        return $this->judge($data, $form_id);
    }

    /**
     * @return string label of the vendor and product in the log line
     */
    abstract protected function getLabel(): string;

    /**
     * @return string id of the provider whose settings hold the secret
     */
    abstract protected function getProviderId(): string;

    /**
     * @return string
     */
    abstract protected function getVerifyUrl(): string;

    /**
     * @param string $secret
     * @param string $response
     * @return array<string, string> the form fields of the request
     */
    abstract protected function buildFields(string $secret, string $response): array;

    /**
     * @return string name of the secret in the provider's settings
     */
    protected function getSecretField(): string
    {
        return "secret_key";
    }

    /**
     * Judges the decoded reply. The default accepts only a success that is
     * the boolean true; a vendor with more to check overrides it.
     *
     * @param array<mixed> $data
     * @param string $form_id
     * @return bool
     */
    protected function judge(array $data, string $form_id): bool
    {
        if (($data["success"] ?? false) === true) {
            return true;
        }

        return $this->fail("rejected" . $this->describeErrorCodes($data["error-codes"] ?? []));
    }

    /**
     * Extra request headers; the secret of the request is in $this->secret.
     *
     * @return string[] "Name: value" lines
     */
    protected function getRequestHeaders(): array
    {
        return [];
    }

    /**
     * Sends the POST request, through the proxy ILIAS is configured with.
     *
     * @param string $url
     * @param array<string, string> $fields
     * @throws \UnexpectedValueException on a status that is not 200 or 5xx
     * @throws \Throwable on a transport failure or a 5xx status
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

        $headers = $this->getRequestHeaders();
        if ($headers !== []) {
            $curl->setOpt(CURLOPT_HTTPHEADER, $headers);
        }

        try {
            $body = $curl->exec();
            $status = (int) $curl->getInfo(CURLINFO_RESPONSE_CODE);
        } finally {
            $curl->close();
        }

        if ($status >= 500) {
            throw new \RuntimeException("HTTP status " . $status);
        }

        if ($status !== 200) {
            throw new \UnexpectedValueException("HTTP status " . $status);
        }

        return is_string($body) ? $body : "";
    }

    /**
     * The error codes a vendor names, as a short suffix for the log line.
     * Only codes of the documented shape are copied.
     *
     * @param mixed $listed
     * @return string
     */
    protected function describeErrorCodes(mixed $listed): string
    {
        $codes = [];

        if (is_array($listed)) {
            foreach ($listed as $code) {
                if (is_string($code) && preg_match("/^[a-z0-9_-]{1,40}$/D", $code) === 1) {
                    $codes[] = $code;
                }
            }
        }

        $codes = array_slice($codes, 0, self::MAX_LOGGED_ERROR_CODES);

        return $codes === [] ? "" : ": " . implode(", ", $codes);
    }

    /**
     * A failure to reach the vendor, which the administrator may choose to
     * tolerate.
     *
     * @param string $reason
     * @return false
     */
    protected function failUnreachable(string $reason): bool
    {
        $this->unreachable = true;

        return $this->fail($reason);
    }

    /**
     * @param string $reason
     * @return false
     */
    protected function fail(string $reason): bool
    {
        $this->getLogger()->warning(
            "AuthGuard: " . $this->getLabel() . " verification failed (reason: " . $reason . ")"
        );

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
