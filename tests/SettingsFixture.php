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

use ILIAS\Filesystem\Filesystem;

/**
 * An ilSetting store and a storage filesystem kept in memory, so the
 * settings can be tested without a database or a data directory.
 */
trait SettingsFixture
{
    /** @var array<string, string> rows of the settings module */
    protected array $rows = [];

    /** @var array<string, string> files of the storage filesystem */
    protected array $files = [];

    /**
     * @return \ilSetting
     */
    protected function makeStore(): \ilSetting
    {
        $store = $this->createMock(\ilSetting::class);
        $store->method("get")->willReturnCallback(
            fn (string $key, ?string $default = null): ?string => $this->rows[$key] ?? $default
        );
        $store->method("set")->willReturnCallback(function (string $key, string $value): void {
            $this->rows[$key] = $value;
        });
        $store->method("deleteAll")->willReturnCallback(function (): void {
            $this->rows = [];
        });

        return $store;
    }

    /**
     * @return Filesystem
     */
    protected function makeStorage(): Filesystem
    {
        $storage = $this->createMock(Filesystem::class);
        $storage->method("has")->willReturnCallback(
            fn (string $path): bool => array_key_exists($path, $this->files)
        );
        $storage->method("read")->willReturnCallback(
            fn (string $path): string => $this->files[$path]
        );
        $storage->method("write")->willReturnCallback(function (string $path, string $content): void {
            $this->files[$path] = $content;
        });
        $storage->method("delete")->willReturnCallback(function (string $path): void {
            unset($this->files[$path]);
        });

        return $storage;
    }

    /**
     * @return \ilAuthGuardSettings
     */
    protected function makeSettings(): \ilAuthGuardSettings
    {
        if (!class_exists(\ilSetting::class)) {
            $this->markTestSkipped("ILIAS core classes not available.");
        }

        return new \ilAuthGuardSettings($this->makeStore(), $this->makeStorage());
    }
}
