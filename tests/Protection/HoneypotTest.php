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

class HoneypotTest extends TestCase
{
    public function testGeneratedNameHasTheExpectedShape(): void
    {
        $this->assertMatchesRegularExpression(
            "/^[a-z]{3,5}_[a-z]{3,5}_[0-9a-f]{6}$/",
            \ilAuthGuardHoneypot::generateName()
        );
    }

    public function testGeneratedNameIsNotAConstant(): void
    {
        $names = [];
        for ($i = 0; $i < 50; $i++) {
            $names[\ilAuthGuardHoneypot::generateName()] = true;
        }

        $this->assertGreaterThan(40, count($names));
    }

    public function testGeneratedNameAvoidsAutofillTriggers(): void
    {
        for ($i = 0; $i < 200; $i++) {
            $name = \ilAuthGuardHoneypot::generateName();
            $this->assertDoesNotMatchRegularExpression(
                "/mail|name|user|phone|tel|addr|city|zip|pass|login/",
                $name
            );
        }
    }

    public function testAbsentFieldIsNotTripped(): void
    {
        $this->assertFalse(\ilAuthGuardHoneypot::isTripped(["other" => "x"], "aux_note_aaaaaa"));
    }

    public function testEmptyAndBlankValuesAreNotTripped(): void
    {
        $this->assertFalse(\ilAuthGuardHoneypot::isTripped(["f" => ""], "f"));
        $this->assertFalse(\ilAuthGuardHoneypot::isTripped(["f" => "  \t"], "f"));
    }

    public function testAnyNonEmptyValueIsTripped(): void
    {
        $this->assertTrue(\ilAuthGuardHoneypot::isTripped(["f" => "x"], "f"));
        $this->assertTrue(\ilAuthGuardHoneypot::isTripped(["f" => "0"], "f"));
    }

    public function testArrayValueIsTripped(): void
    {
        $this->assertTrue(\ilAuthGuardHoneypot::isTripped(["f" => ["x"]], "f"));
        $this->assertTrue(\ilAuthGuardHoneypot::isTripped(["f" => []], "f"));
    }
}
