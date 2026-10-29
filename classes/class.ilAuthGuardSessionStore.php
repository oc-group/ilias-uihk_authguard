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
 * Session access for the per-form state. Tests replace it with an in-memory
 * store.
 */
class ilAuthGuardSessionStore
{
    /**
     * @param string $key
     * @return mixed null when nothing is stored
     */
    public function get(string $key): mixed
    {
        return ilSession::get($key);
    }

    /**
     * @param string $key
     * @param mixed $value
     * @return void
     */
    public function set(string $key, mixed $value): void
    {
        ilSession::set($key, $value);
    }

    /**
     * @param string $key
     * @return void
     */
    public function clear(string $key): void
    {
        ilSession::clear($key);
    }
}
