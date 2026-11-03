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
 * Configuration screen: a read-only list of the checks in force and the
 * choice of the challenge provider. The thresholds are not settings.
 *
 * @ilCtrl_isCalledBy ilAuthGuardConfigGUI: ilObjComponentSettingsGUI
 */
class ilAuthGuardConfigGUI extends ilPluginConfigGUI implements ilCtrlSecurityInterface
{
    /** @var string show the configuration */
    public const CMD_CONFIGURE = "configure";

    /** @var string save the configuration */
    public const CMD_SAVE = "save";

    /** @var string */
    public const TAB_CONFIGURE = "configuration";

    /** @var string query parameter of the component settings object */
    private const PARAM_REF_ID = "ref_id";

    /** @var ilCtrlInterface */
    private ilCtrlInterface $ctrl;

    /** @var ilLanguage */
    private ilLanguage $lng;

    /** @var ilGlobalTemplateInterface */
    private ilGlobalTemplateInterface $tpl;

    /** @var ilTabsGUI */
    private ilTabsGUI $tabs;

    /** @var ilAuthGuardPlugin */
    private ilAuthGuardPlugin $plugin;

    /** @var ilAuthGuardSettings */
    private ilAuthGuardSettings $settings;

    /** @var \ilLogger */
    private \ilLogger $logger;

    /**
     * @return void
     */
    public function __construct()
    {
        global $DIC;

        $this->ctrl = $DIC->ctrl();
        $this->lng = $DIC->language();
        $this->tpl = $DIC->ui()->mainTemplate();
        $this->tabs = $DIC->tabs();
        $this->logger = $DIC->logger()->root();
        $this->plugin = ilAuthGuardPlugin::getInstance();
        $this->settings = new ilAuthGuardSettings();
    }

    /**
     * @param string $cmd
     * @throws ilException when the command is not known
     * @return void
     */
    public function performCommand(string $cmd): void
    {
        $this->initTabs();

        match ($cmd) {
            self::CMD_CONFIGURE => $this->configure(),
            self::CMD_SAVE => $this->save(),
            default => throw new ilException("Unknown command: '" . $cmd . "'"),
        };
    }

    /**
     * Saving changes the protection of every form, so its link carries the
     * request token.
     *
     * @return string[]
     */
    public function getUnsafeGetCommands(): array
    {
        return [self::CMD_SAVE];
    }

    /**
     * No form command is exempt from the token check.
     *
     * @return string[]
     */
    public function getSafePostCommands(): array
    {
        return [];
    }

    /**
     * Whether the request carries the session's request token. ilCtrl only
     * enforces it when the request names a command class, so the save
     * command checks it itself.
     *
     * @return bool
     */
    public static function hasValidToken(): bool
    {
        global $DIC;

        $query = $DIC->http()->wrapper()->query();
        if (!$query->has(ilCtrlInterface::PARAM_CSRF_TOKEN)) {
            return false;
        }

        try {
            $sent = $query->retrieve(
                ilCtrlInterface::PARAM_CSRF_TOKEN,
                $DIC->refinery()->kindlyTo()->string()
            );
        } catch (\Throwable $e) {
            return false;
        }

        return (new ilCtrlTokenRepository())->getToken()->verifyWith($sent);
    }

    /**
     * @return void
     */
    protected function configure(): void
    {
        $this->tpl->setContent($this->initConfigForm()->getHTML());
    }

    /**
     * Validates and stores the choice. Both guards come first: core lets
     * every reader of the component settings reach this class.
     *
     * @return void
     */
    protected function save(): void
    {
        if (!$this->hasWriteAccess()) {
            $this->refuse($this->lng->txt("no_permission"));
            return;
        }

        if (!self::hasValidToken()) {
            $this->refuse($this->plugin->txt("err_invalid_token"));
            return;
        }

        $form = $this->initConfigForm();
        if (!$form->checkInput()) {
            $this->showForm($form);
            return;
        }

        $provider = (string) $form->getInput(ilAuthGuardSettings::FIELD_PROVIDER);
        $site_key = trim((string) $form->getInput(ilAuthGuardSettings::FIELD_SITE_KEY));
        $secret_key = trim((string) $form->getInput(ilAuthGuardSettings::FIELD_SECRET_KEY));

        $errors = ilAuthGuardSettings::validate(
            $provider,
            $site_key,
            $secret_key,
            $this->settings->hasRecaptchaSecretKey()
        );
        if ($errors !== []) {
            $this->showFieldErrors($form, $errors);
            return;
        }

        $this->settings->setProvider($provider);
        $this->settings->setRecaptchaSiteKey($site_key);
        $this->settings->setRecaptchaSecretKey($secret_key);

        $this->logSaved($provider);

        $this->tpl->setOnScreenMessage("success", $this->lng->txt("saved_successfully"), true);
        $this->ctrl->redirect($this, self::CMD_CONFIGURE);
    }

    /**
     * @return ilPropertyFormGUI
     */
    protected function initConfigForm(): ilPropertyFormGUI
    {
        $provider = $this->settings->getProvider();

        $form = new ilPropertyFormGUI();
        $form->setFormAction($this->ctrl->getFormAction($this));
        $form->setTitle($this->plugin->txt("plugin_title"));

        $this->addChecklist($form, $this->settings->getEffectiveProvider());
        $this->addProviderChoice($form, $provider);

        if ($this->hasWriteAccess()) {
            $form->addCommandButton(self::CMD_SAVE, $this->lng->txt("save"));
        }

        return $form;
    }

    /**
     * The checks in force, as ticked read-only boxes. Nothing here is
     * submitted or stored.
     *
     * @param ilPropertyFormGUI $form
     * @param string $effective_provider
     * @return void
     */
    private function addChecklist(ilPropertyFormGUI $form, string $effective_provider): void
    {
        $section = new ilFormSectionHeaderGUI();
        $section->setTitle($this->plugin->txt("cfg_section_checks"));
        $form->addItem($section);

        $timing_info = sprintf(
            $this->plugin->txt("cfg_check_timing_info"),
            (string) ilAuthGuardFormProtection::MIN_SUBMIT_INTERVAL_SECONDS
        );

        $rows = [
            ["timing", "cfg_check_timing", $timing_info, true],
            ["honeypot", "cfg_check_honeypot", $this->plugin->txt("cfg_check_honeypot_info"), true],
            [
                "altcha",
                "cfg_check_altcha",
                $this->plugin->txt("cfg_check_altcha_info"),
                $effective_provider === ilAuthGuardSettings::PROVIDER_ALTCHA,
            ],
            [
                "recaptcha",
                "cfg_check_recaptcha",
                $this->plugin->txt("cfg_check_recaptcha_info"),
                $effective_provider === ilAuthGuardSettings::PROVIDER_RECAPTCHA,
            ],
            ["image", "cfg_check_image", $this->plugin->txt("cfg_check_image_info"), true],
            ["message", "cfg_check_message", $this->plugin->txt("cfg_check_message_info"), true],
        ];

        foreach ($rows as [$name, $title_key, $info, $active]) {
            $item = new ilCheckboxInputGUI($this->plugin->txt($title_key), "check_" . $name);
            $item->setChecked($active);
            $item->setDisabled(true);
            $item->setInfo($info);
            $form->addItem($item);
        }
    }

    /**
     * @param ilPropertyFormGUI $form
     * @param string $provider the stored choice
     * @return void
     */
    private function addProviderChoice(ilPropertyFormGUI $form, string $provider): void
    {
        $section = new ilFormSectionHeaderGUI();
        $section->setTitle($this->plugin->txt("cfg_section_provider"));
        $form->addItem($section);

        $choice = new ilRadioGroupInputGUI($this->plugin->txt("cfg_provider"), ilAuthGuardSettings::FIELD_PROVIDER);
        $choice->setRequired(true);
        $choice->setValue($provider);

        $altcha = new ilRadioOption(
            $this->plugin->txt("cfg_provider_altcha"),
            ilAuthGuardSettings::PROVIDER_ALTCHA,
            $this->plugin->txt("cfg_provider_altcha_info")
        );
        $choice->addOption($altcha);

        $recaptcha = new ilRadioOption(
            $this->plugin->txt("cfg_provider_recaptcha"),
            ilAuthGuardSettings::PROVIDER_RECAPTCHA,
            $this->plugin->txt("cfg_provider_recaptcha_info")
        );

        $site_key = new ilTextInputGUI(
            $this->plugin->txt("cfg_site_key"),
            ilAuthGuardSettings::FIELD_SITE_KEY
        );
        $site_key->setMaxLength(100);
        $site_key->setValue($this->settings->getRecaptchaSiteKey());
        $recaptcha->addSubItem($site_key);

        // Never given a value: the stored key is not sent to the browser.
        $secret_key = new ilPasswordInputGUI(
            $this->plugin->txt("cfg_secret_key"),
            ilAuthGuardSettings::FIELD_SECRET_KEY
        );
        $secret_key->setRetype(false);
        $secret_key->setSkipSyntaxCheck(true);
        $secret_key->setDisableHtmlAutoComplete(true);
        $secret_key->setMaxLength(100);
        $secret_key->setInfo($this->plugin->txt(
            $this->settings->hasRecaptchaSecretKey() ? "cfg_secret_key_stored" : "cfg_secret_key_info"
        ));
        $recaptcha->addSubItem($secret_key);

        $choice->addOption($recaptcha);
        $form->addItem($choice);
    }

    /**
     * Shows the form again with the errors on their fields. The secret key
     * is not repopulated.
     *
     * @param ilPropertyFormGUI $form
     * @param array<string, string> $errors lang key by form field
     * @return void
     */
    private function showFieldErrors(ilPropertyFormGUI $form, array $errors): void
    {
        foreach ($errors as $field => $lang_key) {
            $item = $form->getItemByPostVar($field);
            if ($item !== null) {
                $item->setAlert($this->plugin->txt($lang_key));
            }
        }

        $this->showForm($form);
    }

    /**
     * Shows a submitted form again with the values the user typed, except
     * the secret key, which is never sent back to the browser.
     *
     * @param ilPropertyFormGUI $form
     * @return void
     */
    private function showForm(ilPropertyFormGUI $form): void
    {
        $form->setValuesByPost();

        $secret_key = $form->getItemByPostVar(ilAuthGuardSettings::FIELD_SECRET_KEY);
        if ($secret_key instanceof ilPasswordInputGUI) {
            $secret_key->setValue("");
        }

        $this->tpl->setContent($form->getHTML());
    }

    /**
     * Ends the command with a failure message, writing nothing.
     *
     * @param string $message
     * @return void
     */
    private function refuse(string $message): void
    {
        $this->tpl->setOnScreenMessage("failure", $message, true);
        $this->ctrl->redirect($this, self::CMD_CONFIGURE);
    }

    /**
     * Whether the user may write the component settings. Core only checks
     * "read" before forwarding to a plugin configuration.
     *
     * @return bool
     */
    private function hasWriteAccess(): bool
    {
        global $DIC;

        $query = $DIC->http()->wrapper()->query();
        if (!$query->has(self::PARAM_REF_ID)) {
            return false;
        }

        try {
            $ref_id = $query->retrieve(self::PARAM_REF_ID, $DIC->refinery()->kindlyTo()->int());
        } catch (\Throwable $e) {
            return false;
        }

        return $ref_id > 0 && $DIC->access()->checkAccess("write", "", $ref_id);
    }

    /**
     * One line per save, naming who changed what; the keys never appear.
     *
     * @param string $provider
     * @return void
     */
    private function logSaved(string $provider): void
    {
        global $DIC;

        $this->logger->info(sprintf(
            "AuthGuard: configuration saved by %s (%d). Challenge provider: %s",
            $DIC->user()->getLogin(),
            $DIC->user()->getId(),
            $provider
        ));
    }

    /**
     * @return void
     */
    private function initTabs(): void
    {
        $this->tabs->addTab(
            self::TAB_CONFIGURE,
            $this->lng->txt("settings"),
            $this->ctrl->getLinkTarget($this, self::CMD_CONFIGURE)
        );
        $this->tabs->activateTab(self::TAB_CONFIGURE);
        $this->tpl->setDescription($this->plugin->txt("plugin_description"));
    }
}
