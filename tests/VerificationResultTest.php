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

namespace AuthGuard\Tests;

use PHPUnit\Framework\TestCase;

class VerificationResultTest extends TestCase
{
    public function testPassedResult(): void
    {
        $result = \ilAuthGuardVerificationResult::passed();

        $this->assertTrue($result->isPassed());
        $this->assertSame(\ilAuthGuardVerificationResult::REASON_NONE, $result->getReason());
        $this->assertSame("", $result->getMessage());
    }

    public function testFailedResultCarriesReasonAndMessage(): void
    {
        $result = \ilAuthGuardVerificationResult::failed(
            \ilAuthGuardVerificationResult::REASON_HONEYPOT,
            "Try again"
        );

        $this->assertFalse($result->isPassed());
        $this->assertSame("honeypot", $result->getReason());
        $this->assertSame("Try again", $result->getMessage());
    }

    public function testReasonConstantsAreDistinct(): void
    {
        $reasons = [
            \ilAuthGuardVerificationResult::REASON_NONE,
            \ilAuthGuardVerificationResult::REASON_TIMING,
            \ilAuthGuardVerificationResult::REASON_HONEYPOT,
            \ilAuthGuardVerificationResult::REASON_POW,
            \ilAuthGuardVerificationResult::REASON_CAPTCHA,
            \ilAuthGuardVerificationResult::REASON_MISSING_STATE,
        ];

        $this->assertCount(6, array_unique($reasons));
    }
}
