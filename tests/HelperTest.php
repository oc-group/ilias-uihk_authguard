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

class HelperTest extends TestCase
{
    public function testMatchingAnswerIsValid(): void
    {
        $this->assertTrue(\ilAuthGuardHelper::isValid("abc12", "abc12"));
    }

    public function testComparisonIgnoresCaseAndSurroundingWhitespace(): void
    {
        $this->assertTrue(\ilAuthGuardHelper::isValid("  AbC12 ", "aBc12"));
    }

    public function testWrongAnswerIsInvalid(): void
    {
        $this->assertFalse(\ilAuthGuardHelper::isValid("abc13", "abc12"));
    }

    public function testEmptyExpectedPhraseNeverPasses(): void
    {
        $this->assertFalse(\ilAuthGuardHelper::isValid("", ""));
        $this->assertFalse(\ilAuthGuardHelper::isValid("x", "   "));
    }
}
