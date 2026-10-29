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
 * The hidden decoy input. Its name is random per session and form: a
 * constant name would reach the skip list of any bot written against the
 * published source.
 */
class ilAuthGuardHoneypot
{
    /** @var string[] words no autofill heuristic maps to a known field */
    private const PREFIXES = ["alt", "aux", "ref", "sec", "extra", "other"];

    /** @var string[] */
    private const SUFFIXES = ["code", "note", "key", "tag", "label", "slot"];

    /**
     * @return string e.g. "aux_note_3fa91c"
     */
    public static function generateName(): string
    {
        return self::PREFIXES[random_int(0, count(self::PREFIXES) - 1)]
            . "_"
            . self::SUFFIXES[random_int(0, count(self::SUFFIXES) - 1)]
            . "_"
            . bin2hex(random_bytes(3));
    }

    /**
     * True when the decoy carries any value. An array value counts, since
     * a person can never produce one.
     *
     * @param array<mixed> $body the parsed request body
     * @param string $name the name stored for this render
     * @return bool
     */
    public static function isTripped(array $body, string $name): bool
    {
        if (!array_key_exists($name, $body)) {
            return false;
        }

        $value = $body[$name];

        return !is_string($value) || trim($value) !== "";
    }
}
