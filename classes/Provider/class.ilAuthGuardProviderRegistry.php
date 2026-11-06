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
 * The challenge providers the plugin offers, in the order the
 * configuration screen lists them. Adding a provider means adding its
 * class to PROVIDER_CLASSES.
 */
final class ilAuthGuardProviderRegistry
{
    /** @var string id of the provider used whenever the selected one cannot be */
    public const DEFAULT_ID = ilAuthGuardProviderAltcha::ID;

    /** @var array<int, class-string<ilAuthGuardChallengeProvider>> */
    private const PROVIDER_CLASSES = [
        ilAuthGuardProviderAltcha::class,
        ilAuthGuardProviderRecaptcha::class,
        ilAuthGuardProviderRecaptcha3::class,
        ilAuthGuardProviderTurnstile::class,
        ilAuthGuardProviderHcaptcha::class,
        ilAuthGuardProviderFriendlyCaptcha::class,
    ];

    /** @var array<string, ilAuthGuardChallengeProvider> by id */
    private array $providers = [];

    /**
     * @param ilAuthGuardChallengeProvider[] $providers to offer, default first
     * @return void
     */
    public function __construct(array $providers)
    {
        foreach ($providers as $provider) {
            $this->providers[$provider->getId()] = $provider;
        }
    }

    /**
     * The registry with every provider of the plugin.
     *
     * @param array<string, object> $dependencies collaborator by provider id
     *                                            (tests)
     * @return self
     */
    public static function createDefault(array $dependencies = []): self
    {
        $providers = [];
        foreach (self::PROVIDER_CLASSES as $class) {
            $providers[] = new $class($dependencies[$class::ID] ?? null);
        }

        return new self($providers);
    }

    /**
     * @return string[] the ids of every provider of the plugin
     */
    public static function getKnownIds(): array
    {
        return array_map(static fn (string $class): string => $class::ID, self::PROVIDER_CLASSES);
    }

    /**
     * @param string $id
     * @return bool
     */
    public static function isKnownId(string $id): bool
    {
        return in_array($id, self::getKnownIds(), true);
    }

    /**
     * @return array<string, ilAuthGuardChallengeProvider> by id, display order
     */
    public function all(): array
    {
        return $this->providers;
    }

    /**
     * @param string $id
     * @return ilAuthGuardChallengeProvider|null
     */
    public function find(string $id): ?ilAuthGuardChallengeProvider
    {
        return $this->providers[$id] ?? null;
    }

    /**
     * @return ilAuthGuardChallengeProvider
     */
    public function getDefault(): ilAuthGuardChallengeProvider
    {
        return $this->providers[self::DEFAULT_ID];
    }

    /**
     * The provider the checks actually use: the selected one when its
     * settings are complete, the default otherwise.
     *
     * @param ilAuthGuardSettings $settings
     * @return ilAuthGuardChallengeProvider
     */
    public function resolve(ilAuthGuardSettings $settings): ilAuthGuardChallengeProvider
    {
        $selected = $this->find($settings->getProvider());

        if ($selected !== null && $selected->isConfigured($settings)) {
            return $selected;
        }

        return $this->getDefault();
    }

    /**
     * Checks what a configuration form submits.
     *
     * @param string $id the submitted choice
     * @param array<string, string> $values trimmed value by field name
     * @param array<string, bool> $secrets_stored by field name
     * @return array<string, string> lang key by form input name; an unknown
     *                               choice is reported on "provider"
     */
    public function validate(string $id, array $values, array $secrets_stored): array
    {
        $provider = $this->find($id);
        if ($provider === null) {
            return [ilAuthGuardSettings::FIELD_PROVIDER => "cfg_err_provider"];
        }

        $errors = [];
        foreach ($provider->validate($values, $secrets_stored) as $field => $lang_key) {
            $errors[$id . "_" . $field] = $lang_key;
        }

        return $errors;
    }
}
