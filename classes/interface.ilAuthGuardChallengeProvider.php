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
 * One challenge a visitor answers: the widget that is drawn into the form,
 * the settings it needs and the check of the answer on the server.
 *
 * A provider is added by one class implementing this interface, listed in
 * ilAuthGuardProviderRegistry, plus a BEGIN block in the form template, its
 * script and its lang keys. Nothing else in the plugin names a provider.
 *
 * Lang keys the configuration screen reads for a provider with id "x":
 * "cfg_provider_x" (the option's title) and "cfg_provider_x_info" (its
 * byline), and the label and info keys of each settings field.
 */
interface ilAuthGuardChallengeProvider
{
    /** @var string the answer is genuine */
    public const OUTCOME_PASSED = "passed";

    /** @var string the answer is refused */
    public const OUTCOME_REJECTED = "rejected";

    /** @var string the answer could not be checked: the vendor was not reached */
    public const OUTCOME_UNREACHABLE = "unreachable";

    /**
     * @return string lowercase letters and digits; the stored choice, the
     *                template block name and the prefix of its setting keys
     */
    public function getId(): string;

    /**
     * @return bool whether the visitor's data reaches a third party, which
     *              gives the option the privacy note in the configuration
     */
    public function isExternal(): bool;

    /**
     * @return string name of the POST field that carries the visitor's answer
     */
    public function getPostField(): string;

    /**
     * @return string an ilAuthGuardVerificationResult::REASON_ constant
     */
    public function getFailureReason(): string;

    /**
     * @return string[] names of the template variables of this provider's block
     */
    public function getBlockVariables(): array;

    /**
     * @return ilAuthGuardProviderField[] the settings to fill in
     */
    public function getSettingsFields(): array;

    /**
     * Whether the stored settings are complete. Looks at stored values only:
     * no decryption, no key file access.
     *
     * @param ilAuthGuardSettings $settings
     * @return bool
     */
    public function isConfigured(ilAuthGuardSettings $settings): bool;

    /**
     * Checks what a configuration form submits for this provider.
     *
     * @param array<string, string> $values trimmed value by field name
     * @param array<string, bool> $secrets_stored by field name
     * @return array<string, string> lang key by field name, empty when valid
     */
    public function validate(array $values, array $secrets_stored): array;

    /**
     * Records what the verification of this render needs, before the markup
     * is produced.
     *
     * @param ilAuthGuardProviderContext $context
     * @return void
     */
    public function prepare(ilAuthGuardProviderContext $context): void;

    /**
     * @param ilAuthGuardProviderContext $context
     * @return array<string, string> values of the block variables by name
     */
    public function getRenderVariables(ilAuthGuardProviderContext $context): array;

    /**
     * Checks a non-empty answer. Every failure is logged by the provider
     * with its specific reason. A provider that runs on this server never
     * answers OUTCOME_UNREACHABLE.
     *
     * @param string $answer the value of the POST field
     * @param ilAuthGuardProviderContext $context
     * @return string one of the OUTCOME_ constants
     */
    public function check(string $answer, ilAuthGuardProviderContext $context): string;
}
