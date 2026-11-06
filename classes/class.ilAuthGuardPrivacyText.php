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
 * The draft privacy-policy text of each external provider and the list of
 * what to check before using it. Both are English plain text files, one
 * pair per provider: the draft runs to several paragraphs and a language
 * file value is a single line, and the operator translates the draft into
 * the language of the privacy policy anyway.
 */
final class ilAuthGuardPrivacyText
{
    /**
     * @param string $provider_id id of a provider of the registry
     * @return string|null null when the provider has no draft, as Altcha
     */
    public static function getDraft(string $provider_id): ?string
    {
        $text = self::read($provider_id, "");

        return $text === null ? null : rtrim($text);
    }

    /**
     * @param string $provider_id id of a provider of the registry
     * @return string[] one entry per line of the checks file
     */
    public static function getChecks(string $provider_id): array
    {
        $text = self::read($provider_id, ".checks");
        if ($text === null) {
            return [];
        }

        return array_values(array_filter(
            array_map("trim", explode("\n", $text)),
            static fn (string $line): bool => $line !== ""
        ));
    }

    /**
     * @param string $provider_id
     * @param string $kind "" for the draft, ".checks" for the checks
     * @return string|null
     */
    private static function read(string $provider_id, string $kind): ?string
    {
        if (!ilAuthGuardProviderRegistry::isKnownId($provider_id)) {
            return null;
        }

        $path = self::getPath($provider_id, $kind);
        $text = is_file($path) ? file_get_contents($path) : false;

        return $text === false ? null : $text;
    }

    /**
     * @param string $provider_id
     * @param string $kind
     * @return string
     */
    public static function getPath(string $provider_id, string $kind = ""): string
    {
        return __DIR__ . "/../templates/default/privacy/" . $provider_id . $kind . ".txt";
    }
}
