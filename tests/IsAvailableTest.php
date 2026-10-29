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

class IsAvailableTest extends TestCase
{
    /** @var mixed */
    private $saved_dic;

    private bool $had_dic;

    protected function setUp(): void
    {
        $this->had_dic = array_key_exists("DIC", $GLOBALS);
        $this->saved_dic = $GLOBALS["DIC"] ?? null;
    }

    protected function tearDown(): void
    {
        if ($this->had_dic) {
            $GLOBALS["DIC"] = $this->saved_dic;
        } else {
            unset($GLOBALS["DIC"]);
        }
    }

    public function testFalseWithoutContainer(): void
    {
        unset($GLOBALS["DIC"]);

        $this->assertFalse(\ilAuthGuardFormProtection::isAvailable());
    }

    public function testFalseWhenContainerIsNotAContainer(): void
    {
        $GLOBALS["DIC"] = new \stdClass();

        $this->assertFalse(\ilAuthGuardFormProtection::isAvailable());
    }

    public function testFalseWithoutRepositoryOffset(): void
    {
        $GLOBALS["DIC"] = new \ILIAS\DI\Container();

        $this->assertFalse(\ilAuthGuardFormProtection::isAvailable());
    }

    public function testFalseWhenPluginUnknown(): void
    {
        $this->useRepository(false, false);

        $this->assertFalse(\ilAuthGuardFormProtection::isAvailable());
    }

    public function testFalseWhenPluginInactive(): void
    {
        $this->useRepository(true, false);

        $this->assertFalse(\ilAuthGuardFormProtection::isAvailable());
    }

    public function testTrueWhenPluginActive(): void
    {
        $this->useRepository(true, true);

        $this->assertTrue(\ilAuthGuardFormProtection::isAvailable());
        $this->assertTrue(\ilAuthGuardFormProtection::isAvailable(\ilAuthGuardFormProtection::API_VERSION));
    }

    public function testFalseWhenMinVersionAboveApiVersion(): void
    {
        $this->useRepository(true, true);

        $this->assertFalse(\ilAuthGuardFormProtection::isAvailable(\ilAuthGuardFormProtection::API_VERSION + 1));
    }

    public function testFalseWhenRepositoryThrows(): void
    {
        $repository = $this->createMock(\ilComponentRepository::class);
        $repository->method("hasPluginId")->willThrowException(new \RuntimeException("broken"));

        $dic = new \ILIAS\DI\Container();
        $dic["component.repository"] = static fn () => $repository;
        $GLOBALS["DIC"] = $dic;

        $this->assertFalse(\ilAuthGuardFormProtection::isAvailable());
    }

    private function useRepository(bool $known, bool $active): void
    {
        $info = $this->createMock(\ilPluginInfo::class);
        $info->method("isActive")->willReturn($active);

        $repository = $this->createMock(\ilComponentRepository::class);
        $repository->method("hasPluginId")
            ->with(\ilAuthGuardPlugin::PLUGIN_ID)
            ->willReturn($known);
        $repository->method("getPluginById")->willReturn($info);

        $dic = new \ILIAS\DI\Container();
        $dic["component.repository"] = static fn () => $repository;
        $GLOBALS["DIC"] = $dic;
    }
}
