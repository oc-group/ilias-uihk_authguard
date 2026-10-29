<?php

/**
 * This file is part of AuthGuard Plugin for ILIAS,
 * developed by OC Open Consulting to block automated self-registration
 * submissions with a local image CAPTCHA.
 *
 * @author Dienifer Mendonça <dienifer@oc-group.eu>
 * @author Vincenzo Padula <vincenzo@oc-group.eu>
 * @copyright 2026 OC Open Consulting SB Srl
 * @license http://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */

declare(strict_types=1);

/**
 * Plugin main class. init() runs on every web request, before ILIAS
 * dispatches to any GUI class, which is what lets the plugin reject a
 * registration POST without integrating with the core registration form.
 */
class ilAuthGuardPlugin extends ilUserInterfaceHookPlugin
{
    /** @var string */
    public const PLUGIN_ID = "authgrd";

    /** @var string */
    public const PREFIX = "ui_uihk_authgrd";

    /** @var string form id the registration form is protected under */
    public const REGISTRATION_FORM_ID = "registration";

    /** @var string[] ilCtrl class path of the self-registration GUI, lowercase */
    public const REGISTRATION_CLASS_PATH = ["ilstartupgui", "ilaccountregistrationgui"];

    /** @var self|null */
    protected static ?self $instance = null;

    /**
     * Decides whether this request is the self-registration form's own
     * submit, and if so has the form protection verify it.
     *
     * @return void
     */
    protected function init(): void
    {
        if (self::$instance === null) {
            self::$instance = $this;
        }

        if ($this->shouldInterceptRegistrationSubmit()) {
            $this->enforceFormProtection();
        }
    }

    /**
     * True only for a POST carrying the self-registration form's own
     * "saveForm" submit on the registration GUI's ilCtrl class path. The
     * script name is deliberately not checked: register.php serves only the
     * initial GET, while the submit goes to the generic front controller.
     * "saveForm" is not unique to this form either, so the class-path check
     * is what makes the gate specific.
     *
     * @return bool
     */
    private function shouldInterceptRegistrationSubmit(): bool
    {
        global $DIC;

        if ($DIC->http()->request()->getMethod() !== "POST") {
            return false;
        }

        // The command is resolved by ILIAS's own CSRF-gated routing; a request
        // failing that check is never dispatched here.
        if ($DIC->ctrl()->getCmd() !== "saveForm") {
            return false;
        }

        // getCurrentClassPath() returns declared class names in mixed case, unlike
        // most ilCtrl lookups by name; normalize before comparing.
        if (array_map('strtolower', $DIC->ctrl()->getCurrentClassPath()) !== self::REGISTRATION_CLASS_PATH) {
            return false;
        }

        return true;
    }

    /**
     * Verifies the registration submit and redirects back to the form with
     * the failure message when a check does not pass. The form protection
     * consumes its state first, so the redirected form is rendered anew.
     *
     * @return void
     */
    private function enforceFormProtection(): void
    {
        global $DIC;

        $result = (new ilAuthGuardFormProtection())->verify(
            self::REGISTRATION_FORM_ID,
            $DIC->http()->request()
        );

        if (!$result->isPassed()) {
            ilAuthGuardHelper::redirectWithFailureMessage($result->getMessage());
        }
    }

    /**
     * Returns the shared plugin instance, so the constructor does not run
     * once per caller.
     *
     * @return self
     */
    public static function getInstance(): self
    {
        global $DIC;

        if (self::$instance == null) {
            /** @var ilComponentFactory */
            $component_factory = $DIC["component.factory"];

            /** @var self */
            $plugin = $component_factory->getPlugin(self::PLUGIN_ID);
            self::$instance = $plugin;
        }

        return self::$instance;
    }
}
