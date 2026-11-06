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

use ILIAS\UI\Component\Component;
use ILIAS\UI\Component\Input\Container\Form\Standard;

/**
 * Configuration screen: a read-only list of the checks in force, the
 * form for the challenge provider and the draft privacy texts. The
 * thresholds are not settings.
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

    /** @var \ILIAS\UI\Factory */
    private \ILIAS\UI\Factory $ui_factory;

    /** @var \ILIAS\UI\Renderer */
    private \ILIAS\UI\Renderer $ui_renderer;

    /** @var \Psr\Http\Message\ServerRequestInterface */
    private \Psr\Http\Message\ServerRequestInterface $request;

    /** @var ilAuthGuardPlugin */
    private ilAuthGuardPlugin $plugin;

    /** @var ilAuthGuardSettings */
    private ilAuthGuardSettings $settings;

    /** @var ilAuthGuardProviderRegistry */
    private ilAuthGuardProviderRegistry $registry;

    /** @var ilAuthGuardConfigForm */
    private ilAuthGuardConfigForm $form_builder;

    /** @var ilAuthGuardPrivacyDrafts */
    private ilAuthGuardPrivacyDrafts $privacy_drafts;

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
        $this->ui_factory = $DIC->ui()->factory();
        $this->ui_renderer = $DIC->ui()->renderer();
        $this->request = $DIC->http()->request();
        $this->logger = $DIC->logger()->root();
        $this->plugin = ilAuthGuardPlugin::getInstance();
        $this->settings = new ilAuthGuardSettings();
        $this->registry = ilAuthGuardProviderRegistry::createDefault();
        $this->form_builder = new ilAuthGuardConfigForm(
            $this->ui_factory,
            $DIC->refinery(),
            $this->registry,
            fn (string $lang_key): string => $this->plugin->txt($lang_key)
        );
        $this->privacy_drafts = new ilAuthGuardPrivacyDrafts(
            $this->ui_factory,
            $this->registry,
            fn (string $lang_key): string => $this->plugin->txt($lang_key),
            $this->lng->txt("close"),
            ilAuthGuardPrivacyText::createDefault()
        );
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
        $this->show($this->buildForm(ilAuthGuardConfigState::fromSettings($this->settings, $this->registry)));
    }

    /**
     * Validates and stores the choice. Both guards come first: core lets
     * every reader of the component settings reach this class. The form's
     * own checks run in the fields; a failed one shows the form again with
     * the error on its field.
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

        $stored = ilAuthGuardConfigState::fromSettings($this->settings, $this->registry);

        try {
            $form = $this->buildForm($stored)->withRequest($this->request);
            $data = $form->getData();
        } catch (\Throwable $e) {
            $this->refuse($this->lng->txt("form_input_not_valid"));
            return;
        }

        if ($data === null) {
            $this->show($form);
            return;
        }

        $submitted = ilAuthGuardConfigState::fromFormData($data, $this->settings, $this->registry);
        if ($submitted === null || $submitted->validate($this->registry) !== []) {
            $this->refuse($this->lng->txt("form_input_not_valid"));
            return;
        }

        $submitted->applyTo($this->settings, $this->registry);

        $this->logSaved($submitted->provider);

        $this->tpl->setOnScreenMessage("success", $this->lng->txt("saved_successfully"), true);
        $this->ctrl->redirect($this, self::CMD_CONFIGURE);
    }

    /**
     * The form posts to the save command through ilCtrl's form action,
     * which carries the request token. Without write access the inputs are
     * read-only.
     *
     * @param ilAuthGuardConfigState $state
     * @return Standard
     */
    private function buildForm(ilAuthGuardConfigState $state): Standard
    {
        return $this->form_builder->build(
            $this->ctrl->getFormAction($this, self::CMD_SAVE),
            $state,
            !$this->hasWriteAccess(),
            $this->lng->txt("save")
        );
    }

    /**
     * Puts the page together: the checks in force, the form and the draft
     * privacy texts. The checks and the texts sit outside the form.
     *
     * @param Standard $form
     * @return void
     */
    private function show(Standard $form): void
    {
        $this->tpl->setContent($this->ui_renderer->render(
            [$this->createChecklist(), $form, ...$this->privacy_drafts->createComponents()]
        ));
    }

    /**
     * The checks that always run, as a read-only list. The challenge
     * provider is deliberately absent: it is a choice, made in the form, so
     * a provider added later can never appear in this list.
     *
     * @return Component
     */
    private function createChecklist(): Component
    {
        $timing_info = sprintf(
            $this->plugin->txt("cfg_check_timing_info"),
            (string) ilAuthGuardFormProtection::MIN_SUBMIT_INTERVAL_SECONDS
        );

        $items = [
            $this->plugin->txt("cfg_check_timing") => $timing_info,
            $this->plugin->txt("cfg_check_honeypot") => $this->plugin->txt("cfg_check_honeypot_info"),
            $this->plugin->txt("cfg_check_image") => $this->plugin->txt("cfg_check_image_info"),
            $this->plugin->txt("cfg_check_message") => $this->plugin->txt("cfg_check_message_info"),
        ];

        return $this->ui_factory->panel()->standard(
            $this->plugin->txt("cfg_section_checks"),
            $this->ui_factory->listing()->descriptive($items)
        );
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
