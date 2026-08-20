<?php

/**
 * This file is part of AuthGuard Plugin for ILIAS,
 * developed by OC Open Consulting to block automated self-registration
 * submissions with a local image CAPTCHA.
 *
 * @author Dienifer Mendonça <dienifer@oc-group.eu>
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

    /** @var float minimum seconds between the form being rendered and its submit; may be fractional */
    public const MIN_SUBMIT_INTERVAL_SECONDS = 2.0;

    /** @var string[] ilCtrl class path of the self-registration GUI, lowercase */
    public const REGISTRATION_CLASS_PATH = ["ilstartupgui", "ilaccountregistrationgui"];

    /** @var self|null */
    protected static ?self $instance = null;

    /**
     * Decides whether this request is the self-registration form's own
     * submit, and if so enforces the CAPTCHA.
     *
     * @return void
     */
    protected function init(): void
    {
        if (self::$instance === null) {
            self::$instance = $this;
        }

        if ($this->shouldInterceptRegistrationSubmit()) {
            $this->enforceSubmitTiming();
            $this->enforceCaptcha();
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
     * Rejects a submit that arrives sooner after the form was rendered than a
     * person could have filled it in. A session with no render timestamp is
     * left alone: the CAPTCHA check already rejects one that holds no expected
     * phrase, and this check has nothing to measure against.
     *
     * @return void
     */
    private function enforceSubmitTiming(): void
    {
        $rendered_at = ilAuthGuardHelper::readFormRenderedTime();

        if ($rendered_at === null) {
            return;
        }

        if ((microtime(true) - $rendered_at) >= self::MIN_SUBMIT_INTERVAL_SECONDS) {
            return;
        }

        ilAuthGuardHelper::redirectWithFailureMessage($this->txt("submit_too_fast"));
    }

    /**
     * Compares the submitted code against the phrase held in the session and
     * redirects back to the form on failure. The phrase is consumed before
     * the comparison, so it can never be tried twice. An empty field and a
     * missing phrase share one message, a wrong code gets another.
     *
     * @return void
     */
    private function enforceCaptcha(): void
    {
        global $DIC;

        $post = $DIC->http()->wrapper()->post();
        $submitted = "";
        if ($post->has("captcha_code")) {
            try {
                $submitted = $post->retrieve("captcha_code", $DIC->refinery()->kindlyTo()->string());
            } catch (\UnexpectedValueException) {
                // An array-valued field must fail closed here, not raise an error.
                $submitted = "";
            }
        }

        $expected = ilAuthGuardHelper::readExpectedPhrase();
        ilAuthGuardHelper::clearExpectedPhrase();

        if (trim($submitted) === "" || trim($expected) === "") {
            ilAuthGuardHelper::redirectWithFailureMessage($this->txt("captcha_required"));
        }

        if (ilAuthGuardHelper::isValid($submitted, $expected)) {
            return;
        }

        ilAuthGuardHelper::redirectWithFailureMessage($this->txt("captcha_validation_failed"));
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
