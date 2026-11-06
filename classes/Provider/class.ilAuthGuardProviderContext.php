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
 * What a provider is handed to render a form or verify its submit: the
 * settings, the logger, the form and its session state, and the two URL
 * builders of the form protection.
 */
final class ilAuthGuardProviderContext
{
    /** @var ilAuthGuardSettings */
    public readonly ilAuthGuardSettings $settings;

    /** @var \ilLogger */
    public readonly \ilLogger $logger;

    /** @var ilAuthGuardFormState */
    public readonly ilAuthGuardFormState $state;

    /** @var string */
    public readonly string $form_id;

    /** @var Closure(string): string */
    private Closure $endpoint_url;

    /** @var Closure(string): string */
    private Closure $asset_url;

    /**
     * @param ilAuthGuardSettings $settings
     * @param \ilLogger $logger
     * @param ilAuthGuardFormState $state
     * @param Closure(string): string $endpoint_url URL of a command of the form
     * @param Closure(string): string $asset_url URL of a file of the plugin
     * @return void
     */
    public function __construct(
        ilAuthGuardSettings $settings,
        \ilLogger $logger,
        ilAuthGuardFormState $state,
        Closure $endpoint_url,
        Closure $asset_url
    ) {
        $this->settings = $settings;
        $this->logger = $logger;
        $this->state = $state;
        $this->form_id = $state->getFormId();
        $this->endpoint_url = $endpoint_url;
        $this->asset_url = $asset_url;
    }

    /**
     * @param string $command an ilAuthGuardGUI command
     * @return string
     */
    public function getEndpointUrl(string $command): string
    {
        return ($this->endpoint_url)($command);
    }

    /**
     * @param string $path starting with a slash, relative to the plugin
     * @return string
     */
    public function getAssetUrl(string $path): string
    {
        return ($this->asset_url)($path);
    }
}
