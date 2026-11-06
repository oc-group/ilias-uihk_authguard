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

use ILIAS\Data\Password;

/**
 * What the configuration form shows or submits, without any UI component:
 * the chosen provider, the value of each provider's settings, which secrets
 * are stored, and the unreachable-vendor choice. It reads the stored
 * settings, reads the data a submitted form hands over, checks it with the
 * providers and writes it back.
 */
final class ilAuthGuardConfigState
{
    /** @var string key of the form section */
    public const SECTION = "settings";

    /** @var string key of the provider choice inside the section */
    public const KEY_PROVIDER = "provider";

    /** @var string key of the unreachable-vendor checkbox inside the section */
    public const KEY_ACCEPT = "accept_when_unreachable";

    /** @var string id of the chosen provider */
    public readonly string $provider;

    /** @var array<string, array<string, string>> value by field name by provider id; secrets only when submitted */
    public readonly array $values;

    /** @var array<string, array<string, bool>> whether a secret is stored, by field name by provider id */
    public readonly array $secrets_stored;

    /** @var bool */
    public readonly bool $accept;

    /**
     * @param string $provider
     * @param array<string, array<string, string>> $values
     * @param array<string, array<string, bool>> $secrets_stored
     * @param bool $accept
     * @return void
     */
    public function __construct(string $provider, array $values, array $secrets_stored, bool $accept)
    {
        $this->provider = $provider;
        $this->values = $values;
        $this->secrets_stored = $secrets_stored;
        $this->accept = $accept;
    }

    /**
     * The stored state. Plain settings fall back to their default; a secret
     * is only reported as stored, never read.
     *
     * @param ilAuthGuardSettings $settings
     * @param ilAuthGuardProviderRegistry $registry
     * @return self
     */
    public static function fromSettings(ilAuthGuardSettings $settings, ilAuthGuardProviderRegistry $registry): self
    {
        $values = [];
        $stored = [];

        foreach ($registry->all() as $id => $provider) {
            foreach ($provider->getSettingsFields() as $field) {
                if ($field->isSecret()) {
                    $stored[$id][$field->name] = $settings->hasProviderSecret($id, $field->name);
                    continue;
                }

                $values[$id][$field->name] = $settings->getProviderValue($id, $field->name, $field->default);
            }
        }

        return new self($settings->getProvider(), $values, $stored, $settings->isAcceptWhenUnreachable());
    }

    /**
     * Reads the data of a submitted and valid form: the section holds the
     * chosen provider with the values of its fields, and the checkbox. Only
     * the chosen provider's values are present. A password arrives as an
     * ILIAS Data Password, a text as a string.
     *
     * @param mixed $data what the form's getData() returned
     * @param ilAuthGuardSettings $settings tells which secrets are stored
     * @param ilAuthGuardProviderRegistry $registry
     * @return self|null null when the data does not have the expected shape
     */
    public static function fromFormData(
        mixed $data,
        ilAuthGuardSettings $settings,
        ilAuthGuardProviderRegistry $registry
    ): ?self {
        $section = is_array($data) ? ($data[self::SECTION] ?? null) : null;
        $choice = is_array($section) ? ($section[self::KEY_PROVIDER] ?? null) : null;
        if (!is_array($choice) || count($choice) !== 2 || !is_string($choice[0]) || !is_array($choice[1])) {
            return null;
        }

        $provider = $registry->find($choice[0]);
        if ($provider === null) {
            return null;
        }

        $values = [];
        $stored = [];
        foreach ($provider->getSettingsFields() as $field) {
            $values[$provider->getId()][$field->name] = trim(self::asString($choice[1][$field->name] ?? ""));
            if ($field->isSecret()) {
                $stored[$provider->getId()][$field->name] = $settings->hasProviderSecret(
                    $provider->getId(),
                    $field->name
                );
            }
        }

        return new self($provider->getId(), $values, $stored, ($section[self::KEY_ACCEPT] ?? false) === true);
    }

    /**
     * This state with the submitted choice, checkbox and values of the
     * chosen provider laid over it, for showing a form again.
     *
     * @param self $submitted
     * @return self
     */
    public function overlay(self $submitted): self
    {
        $values = $this->values;
        foreach ($submitted->values as $id => $fields) {
            $values[$id] = array_merge($values[$id] ?? [], $fields);
        }

        return new self($submitted->provider, $values, $this->secrets_stored, $submitted->accept);
    }

    /**
     * Checks the chosen provider's values with the provider.
     *
     * @param ilAuthGuardProviderRegistry $registry
     * @return array<string, string> lang key by form input name
     */
    public function validate(ilAuthGuardProviderRegistry $registry): array
    {
        return $registry->validate(
            $this->provider,
            $this->values[$this->provider] ?? [],
            $this->secrets_stored[$this->provider] ?? []
        );
    }

    /**
     * Stores the choice, the checkbox and the chosen provider's settings. A
     * secret left empty keeps the stored one.
     *
     * @param ilAuthGuardSettings $settings
     * @param ilAuthGuardProviderRegistry $registry
     * @throws InvalidArgumentException when the provider is unknown
     * @return void
     */
    public function applyTo(ilAuthGuardSettings $settings, ilAuthGuardProviderRegistry $registry): void
    {
        $provider = $registry->find($this->provider);
        if ($provider === null) {
            throw new InvalidArgumentException("Unknown challenge provider.");
        }

        $settings->setProvider($this->provider);
        $settings->setAcceptWhenUnreachable($this->accept);

        foreach ($provider->getSettingsFields() as $field) {
            $value = $this->values[$this->provider][$field->name] ?? "";

            if ($field->isSecret()) {
                $settings->setProviderSecret($this->provider, $field->name, $value);
                continue;
            }

            $settings->setProviderValue($this->provider, $field->name, $value);
        }
    }

    /**
     * @param mixed $value
     * @return string
     */
    private static function asString(mixed $value): string
    {
        if ($value instanceof Password) {
            return $value->toString();
        }

        return is_string($value) ? $value : "";
    }
}
