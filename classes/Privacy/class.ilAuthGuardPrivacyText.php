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
 * The draft privacy-policy text of an external provider and the list of what
 * to check before using it. Both are English plain text, built from the one
 * template templates/default/tpl.privacy_draft.txt and the facts of the
 * provider: the draft runs to several paragraphs and a language file value
 * is a single line, and the operator translates the draft into the language
 * of the privacy policy anyway.
 *
 * The template is filled by plain substitution of its {{KEY}} markers, not
 * by ilTemplate: the output is plain text, not HTML, ilTemplate would treat
 * the square brackets and the braces of the text as its own syntax, and the
 * substitution needs no ILIAS context. Only fixed strings of the provider
 * classes reach it, never a request value. strtr() replaces in one pass, so
 * a value is never scanned for markers again.
 */
final class ilAuthGuardPrivacyText
{
    /** @var string line of the template that starts the checks */
    private const CHECKS_MARKER = "@@CHECKS@@";

    /**
     * @param ilAuthGuardPrivacyFacts $facts
     * @return string
     */
    public static function getDraft(ilAuthGuardPrivacyFacts $facts): string
    {
        return rtrim(self::fill($facts)[0]);
    }

    /**
     * @param ilAuthGuardPrivacyFacts $facts
     * @return string[] one entry per check
     */
    public static function getChecks(ilAuthGuardPrivacyFacts $facts): array
    {
        return array_values(array_filter(
            array_map("trim", explode("
", self::fill($facts)[1])),
            static fn (string $line): bool => $line !== ""
        ));
    }

    /**
     * @return string
     */
    public static function getTemplatePath(): string
    {
        return __DIR__ . "/../../templates/default/tpl.privacy_draft.txt";
    }

    /**
     * @param ilAuthGuardPrivacyFacts $facts
     * @return array{0: string, 1: string} draft and checks, still as text
     */
    private static function fill(ilAuthGuardPrivacyFacts $facts): array
    {
        $template = file_get_contents(self::getTemplatePath());
        if ($template === false) {
            throw new RuntimeException("The privacy draft template is missing.");
        }

        $filled = strtr($template, [
            "{{NAME}}" => $facts->name,
            "{{SERVICE}}" => $facts->service,
            "{{PURPOSE}}" => $facts->purpose,
            "{{ABOUT}}" => $facts->about,
            "{{PROCESSING}}" => $facts->processing,
            "{{CONTROLLER}}" => $facts->controller,
            "{{CONSENT_SUBJECT}}" => $facts->consent_subject,
            "{{MORE_INFORMATION}}" => $facts->more_information,
            "{{SPECIFIC_CHECKS}}" => implode("
", $facts->checks),
        ]);
        [$draft, $checks] = explode(self::CHECKS_MARKER, $filled, 2) + [1 => ""];

        return [$draft, $checks];
    }
}
