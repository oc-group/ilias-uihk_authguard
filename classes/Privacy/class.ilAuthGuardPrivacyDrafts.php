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
use ILIAS\UI\Factory as UIFactory;

/**
 * The draft privacy texts as UI components: a heading and one button, and
 * the one modal the button opens. The modal has the notice and the intro at
 * the top and, for each external provider, a section with its name, the
 * draft in a read-only text area and the list of what to check. The
 * components belong below the configuration form, not inside it: a button
 * inside a form submits it, and the modal must not carry form fields.
 */
final class ilAuthGuardPrivacyDrafts
{
    /** @var UIFactory */
    private UIFactory $ui;

    /** @var ilAuthGuardProviderRegistry */
    private ilAuthGuardProviderRegistry $registry;

    /** @var Closure(string): string translates a lang key of the plugin */
    private Closure $txt;

    /** @var string label of the button that closes the modal */
    private string $close_label;

    /** @var ilAuthGuardPrivacyText builds the drafts and the checks from the template */
    private ilAuthGuardPrivacyText $text;

    /**
     * @param UIFactory $ui
     * @param ilAuthGuardProviderRegistry $registry
     * @param Closure(string): string $txt
     * @param string $close_label
     * @param ilAuthGuardPrivacyText $text
     * @return void
     */
    public function __construct(
        UIFactory $ui,
        ilAuthGuardProviderRegistry $registry,
        Closure $txt,
        string $close_label,
        ilAuthGuardPrivacyText $text
    ) {
        $this->ui = $ui;
        $this->registry = $registry;
        $this->txt = $txt;
        $this->close_label = $close_label;
        $this->text = $text;
    }

    /**
     * @return Component[] heading, button and modal; empty without drafts
     */
    public function createComponents(): array
    {
        $content = [
            $this->ui->messageBox()->info($this->txt("cfg_privacy_draft_notice")),
            $this->ui->legacy("<p>" . $this->escape($this->txt("cfg_privacy_drafts_intro")) . "</p>"),
        ];

        $found = false;
        foreach ($this->registry->all() as $provider) {
            $facts = $provider->getPrivacyFacts();
            if ($facts === null) {
                continue;
            }

            $found = true;
            $content[] = $this->ui->legacy(
                "<h4>" . $this->escape($this->txt("cfg_provider_" . $provider->getId())) . "</h4>"
                . '<pre class="ilAuthGuardDraft" role="region" tabindex="0"'
                . ' aria-label="' . $this->escape($this->txt("cfg_privacy_draft_label")) . '">'
                . $this->escape($this->text->getDraft($facts)) . "</pre>"
                . "<h5>" . $this->escape($this->txt("cfg_privacy_checks_title")) . "</h5>"
            );
            $content[] = $this->ui->listing()->unordered($this->text->getChecks($facts));
        }

        if (!$found) {
            return [];
        }

        $modal = $this->ui->modal()
            ->roundtrip($this->txt("cfg_privacy_drafts_title"), $content)
            ->withCancelButtonLabel($this->close_label);

        return [
            $this->ui->legacy("<h3>" . $this->escape($this->txt("cfg_privacy_drafts_title")) . "</h3>"),
            $this->ui->button()->standard($this->txt("cfg_privacy_draft_show"), $modal->getShowSignal()),
            $modal,
        ];
    }

    /**
     * @param string $lang_key
     * @return string
     */
    private function txt(string $lang_key): string
    {
        return ($this->txt)($lang_key);
    }

    /**
     * @param string $text
     * @return string
     */
    private function escape(string $text): string
    {
        return htmlspecialchars($text, ENT_QUOTES, "UTF-8");
    }
}
