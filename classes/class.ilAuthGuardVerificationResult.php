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
 * Outcome of a form verification. The message is translated and safe to
 * show to the visitor.
 *
 * @api
 */
class ilAuthGuardVerificationResult
{
    /** @var string */
    public const REASON_NONE = "none";

    /** @var string */
    public const REASON_TIMING = "timing";

    /** @var string */
    public const REASON_HONEYPOT = "honeypot";

    /** @var string */
    public const REASON_POW = "pow";

    /** @var string */
    public const REASON_CAPTCHA = "captcha";

    /** @var string */
    public const REASON_MISSING_STATE = "missing_state";

    /** @var string */
    private string $reason;

    /** @var string */
    private string $message;

    /**
     * @param string $reason one of the REASON_ constants
     * @param string $message
     * @return void
     */
    private function __construct(string $reason, string $message)
    {
        $this->reason = $reason;
        $this->message = $message;
    }

    /**
     * @return self
     */
    public static function passed(): self
    {
        return new self(self::REASON_NONE, "");
    }

    /**
     * @param string $reason one of the REASON_ constants except REASON_NONE
     * @param string $message translated, shown to the visitor
     * @return self
     */
    public static function failed(string $reason, string $message): self
    {
        return new self($reason, $message);
    }

    /**
     * @return bool
     */
    public function isPassed(): bool
    {
        return $this->reason === self::REASON_NONE;
    }

    /**
     * @return string one of the REASON_ constants
     */
    public function getReason(): string
    {
        return $this->reason;
    }

    /**
     * @return string empty when the check passed
     */
    public function getMessage(): string
    {
        return $this->message;
    }
}
