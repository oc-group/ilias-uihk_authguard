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

/**
 * In-memory stand-in for the session, so the form state can be tested
 * without bootstrapping ILIAS.
 */
class ArraySessionStore extends \ilAuthGuardSessionStore
{
    /** @var array<string, mixed> */
    public array $data = [];

    /**
     * @param string $key
     * @return mixed
     */
    public function get(string $key): mixed
    {
        return $this->data[$key] ?? null;
    }

    /**
     * @param string $key
     * @param mixed $value
     * @return void
     */
    public function set(string $key, mixed $value): void
    {
        $this->data[$key] = $value;
    }

    /**
     * @param string $key
     * @return void
     */
    public function clear(string $key): void
    {
        unset($this->data[$key]);
    }
}
