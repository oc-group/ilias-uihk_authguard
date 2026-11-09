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
use ILIAS\Refinery\Factory as Refinery;
use ILIAS\UI\Component\Input\Container\Form\FormInput;
use ILIAS\UI\Component\Input\Container\Form\Standard;
use ILIAS\UI\Factory as UIFactory;

/**
 * Builds the configuration form with the UI Framework: one section with a
 * switchable group (one group per provider, with that provider's fields)
 * and the unreachable-vendor checkbox. Each field checks itself with the
 * provider, through a Refinery constraint, so a refused value is reported
 * on its own field.
 */
final class ilAuthGuardConfigForm
{
    /** @var UIFactory */
    private UIFactory $ui;

    /** @var Refinery */
    private Refinery $refinery;

    /** @var ilAuthGuardProviderRegistry */
    private ilAuthGuardProviderRegistry $registry;

    /** @var Closure(string): string translates a lang key of the plugin */
    private Closure $txt;

    /**
     * @param UIFactory $ui
     * @param Refinery $refinery
     * @param ilAuthGuardProviderRegistry $registry
     * @param Closure(string): string $txt
     * @return void
     */
    public function __construct(
        UIFactory $ui,
        Refinery $refinery,
        ilAuthGuardProviderRegistry $registry,
        Closure $txt
    ) {
        $this->ui = $ui;
        $this->refinery = $refinery;
        $this->registry = $registry;
        $this->txt = $txt;
    }

    /**
     * @param string $post_url
     * @param ilAuthGuardConfigState $state what the inputs show
     * @param bool $disabled whether the inputs are read-only
     * @param string $submit_label
     * @return Standard
     */
    public function build(
        string $post_url,
        ilAuthGuardConfigState $state,
        bool $disabled,
        string $submit_label
    ): Standard {
        $field = $this->ui->input()->field();

        $groups = [];
        foreach ($this->registry->all() as $id => $provider) {
            $inputs = [];
            foreach ($provider->getSettingsFields() as $setting) {
                $inputs[$setting->name] = $this->createInput($provider, $setting, $state);
            }

            $groups[$id] = $field->group($inputs, $this->txt("cfg_provider_" . $id), $this->getByline($provider));
        }

        $choice = $field->switchableGroup($groups, $this->txt("cfg_provider"))->withRequired(true);
        if (array_key_exists($state->provider, $groups)) {
            $choice = $choice->withValue($state->provider);
        }

        $accept = $field->checkbox(
            $this->txt("cfg_accept_unreachable"),
            $this->txt("cfg_accept_unreachable_info")
        )->withValue($state->accept);

        $section = $field->section(
            [
                ilAuthGuardConfigState::KEY_PROVIDER => $choice,
                ilAuthGuardConfigState::KEY_ACCEPT => $accept,
            ],
            $this->txt("cfg_section_provider")
        );

        if ($disabled) {
            $section = $section->withDisabled(true);
        }

        return $this->ui->input()->container()->form()
            ->standard($post_url, [ilAuthGuardConfigState::SECTION => $section])
            ->withSubmitLabel($submit_label);
    }

    /**
     * The byline of a provider's option. An external provider gets the
     * shared privacy-policy note appended.
     *
     * @param ilAuthGuardChallengeProvider $provider
     * @return string
     */
    private function getByline(ilAuthGuardChallengeProvider $provider): string
    {
        $info = $this->txt("cfg_provider_" . $provider->getId() . "_info");

        return $provider->isExternal() ? $info . " " . $this->txt("cfg_provider_external_note") : $info;
    }

    /**
     * @param ilAuthGuardChallengeProvider $provider
     * @param ilAuthGuardProviderField $setting
     * @param ilAuthGuardConfigState $state
     * @return FormInput
     */
    private function createInput(
        ilAuthGuardChallengeProvider $provider,
        ilAuthGuardProviderField $setting,
        ilAuthGuardConfigState $state
    ): FormInput {
        return $this->createBaseInput($provider->getId(), $setting, $state)
            ->withAdditionalTransformation($this->createCheck($provider, $setting, $state))
            ->withAdditionalTransformation($this->refinery->custom()->transformation(
                static fn ($value) => $value instanceof Password ? $value : trim((string) $value)
            ));
    }

    /**
     * @param string $id provider id
     * @param ilAuthGuardProviderField $setting
     * @param ilAuthGuardConfigState $state
     * @return FormInput
     */
    private function createBaseInput(
        string $id,
        ilAuthGuardProviderField $setting,
        ilAuthGuardConfigState $state
    ): FormInput {
        $label = $this->txt($setting->label_key);
        $info = $setting->info_key === "" ? null : $this->txt($setting->info_key);
        $field = $this->ui->input()->field();

        if ($setting->isSecret()) {
            // Never given a value: the stored secret never goes to the browser.
            $stored = $state->secrets_stored[$id][$setting->name] ?? false;

            return $field->password($label, $this->txt($stored ? "cfg_secret_key_stored" : "cfg_secret_key_info"));
        }

        $current = $state->values[$id][$setting->name] ?? $setting->default;

        if ($setting->type === ilAuthGuardProviderField::TYPE_SELECT) {
            $options = [];
            foreach ($setting->options as $value => $title_key) {
                $options[$value] = $this->txt($title_key);
            }

            // Not required: KS would put the asterisk on the whole provider option.
            // The provider check refuses the empty option when it is selected.
            return $field->select($label, $options, $info)
                ->withValue(array_key_exists($current, $options) ? $current : $setting->default);
        }

        return $field->text($label, $info)->withMaxLength($setting->max_length)->withValue($current);
    }

    /**
     * The provider's own check of this one field. A secret may be empty
     * when one is stored.
     *
     * @param ilAuthGuardChallengeProvider $provider
     * @param ilAuthGuardProviderField $setting
     * @param ilAuthGuardConfigState $state
     * @return \ILIAS\Refinery\Constraint
     */
    private function createCheck(
        ilAuthGuardChallengeProvider $provider,
        ilAuthGuardProviderField $setting,
        ilAuthGuardConfigState $state
    ): \ILIAS\Refinery\Constraint {
        $name = $setting->name;
        $stored = $state->secrets_stored[$provider->getId()][$name] ?? false;

        return $this->refinery->custom()->constraint(
            static function ($value) use ($provider, $name, $stored): bool {
                $text = $value instanceof Password ? $value->toString() : trim((string) $value);

                return !array_key_exists($name, $provider->validate([$name => $text], [$name => $stored]));
            },
            $this->txt($setting->error_key)
        );
    }

    /**
     * @param string $lang_key
     * @return string
     */
    private function txt(string $lang_key): string
    {
        return ($this->txt)($lang_key);
    }
}
