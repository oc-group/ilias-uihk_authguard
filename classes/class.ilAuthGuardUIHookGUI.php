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
 * Splices the CAPTCHA widget (image + reload control + text input) into the
 * self-registration form, just before its submit button. Rendering only: the
 * template_get hook fires during HTML rendering and never inside a GUI's own
 * POST-handling branch, so it cannot be relied on for the check itself.
 * Enforcement is server-side and independent of this class.
 */
class ilAuthGuardUIHookGUI extends ilUIHookPluginGUI
{
    /** @var string tpl_id of ilPropertyFormGUI's rendered template */
    private const PROPERTY_FORM_TPL_ID = "Services/Form/tpl.property_form.html";

    /** @var ilAuthGuardPlugin */
    protected ilAuthGuardPlugin $plugin;

    /** @var bool the widget must be injected at most once per request */
    protected static bool $widget_injected = false;

    /**
     * @return void
     */
    public function __construct()
    {
        $this->plugin = ilAuthGuardPlugin::getInstance();
    }

    /**
     * @param string $a_comp
     * @param string $a_part
     * @param array<string, mixed> $a_par
     * @return array<string, mixed> the HTML operation (APPEND, PREPEND, REPLACE, KEEP) and the HTML
     */
    public function getHTML(
        string $a_comp,
        string $a_part,
        array $a_par = []
    ): array {
        if ($this->isRegistrationFormRender($a_part, $a_par)) {
            return $this->injectCaptchaWidget($a_par);
        }

        return parent::getHTML($a_comp, $a_part, $a_par);
    }

    /**
     * All conditions that decide whether the widget should be spliced into
     * this getHTML() call.
     *
     * @param string $a_part
     * @param array<string, mixed> $a_par
     * @return bool
     */
    private function isRegistrationFormRender(string $a_part, array $a_par): bool
    {
        global $DIC;

        if (self::$widget_injected || $a_part !== "template_get") {
            return false;
        }

        if (($a_par["tpl_id"] ?? "") !== self::PROPERTY_FORM_TPL_ID) {
            return false;
        }

        // getCurrentClassPath() returns declared class names in mixed case, unlike
        // most ilCtrl lookups by name; normalize before comparing.
        if (
            array_map('strtolower', $DIC->ctrl()->getCurrentClassPath())
            !== ilAuthGuardPlugin::REGISTRATION_CLASS_PATH
        ) {
            return false;
        }

        return true;
    }

    /**
     * Builds the widget markup and splices it into the form HTML just before
     * the submit-button row, setting the once-per-request guard. A missing
     * anchor is logged rather than ignored: enforcement keeps rejecting every
     * submission afterwards, so a silent failure would leave no trail.
     *
     * @param array<string, mixed> $a_par
     * @return array<string, mixed>
     */
    private function injectCaptchaWidget(array $a_par): array
    {
        global $DIC;

        self::$widget_injected = true;
        ilAuthGuardHelper::storeFormRenderedTime(microtime(true));

        $widget_html = $this->renderWidget($DIC);
        $html = (string) ($a_par["html"] ?? "");

        // "ilFormFooter row clearfix" wraps only the submit-button row;
        // prepending the widget there puts it right before the button.
        $replaced = preg_replace(
            '/<div class="ilFormFooter row clearfix">/',
            $widget_html . '<div class="ilFormFooter row clearfix">',
            $html,
            1,
            $replacement_count
        );

        if ($replaced === null || $replacement_count === 0) {
            $DIC->logger()->root()->error(
                "The CAPTCHA widget could not be injected into the registration form; "
                . "submissions will therefore be rejected."
            );
        }

        return [
            "mode" => ilUIHookPluginGUI::REPLACE,
            "html" => $replaced ?? $html,
        ];
    }

    /**
     * Renders the widget template and registers its CSS/JS. Reached only once
     * an injection is certain, so neither the stylesheet nor the reload
     * script load on unrelated pages.
     *
     * @param \ILIAS\DI\Container $dic
     * @return string
     */
    private function renderWidget(\ILIAS\DI\Container $dic): string
    {
        $image_src = $dic->ctrl()->getLinkTargetByClass(
            [ilUIPluginRouterGUI::class, ilAuthGuardGUI::class],
            ilAuthGuardGUI::CMD_SHOW_IMAGE
        );

        $main_tpl = $dic->ui()->mainTemplate();
        $main_tpl->addCss($this->plugin->getDirectory() . "/css/captcha.css");

        // json_encode() gives a safely quoted JS string literal; raw
        // concatenation is the wrong tool in a JS-string context.
        $image_src_js = json_encode($image_src, JSON_THROW_ON_ERROR);

        $tpl = $this->plugin->getTemplate("default/tpl.captcha_widget.html");
        $tpl->setVariable("CAPTCHA_IMG_SRC", htmlspecialchars($image_src, ENT_QUOTES, "UTF-8"));
        $tpl->setVariable("CAPTCHA_IMG_SRC_JS", $image_src_js);
        $tpl->setVariable("CAPTCHA_ALT", $this->plugin->txt("captcha_alt"));
        $tpl->setVariable("CAPTCHA_LABEL", $this->plugin->txt("captcha_label"));
        $tpl->setVariable("CAPTCHA_INFO", $this->plugin->txt("captcha_info"));
        $tpl->setVariable("CAPTCHA_RELOAD_TEXT", $this->plugin->txt("captcha_reload"));

        return $tpl->get();
    }
}
