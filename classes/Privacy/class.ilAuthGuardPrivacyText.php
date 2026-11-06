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
 * The draft privacy-policy text of an external provider and the list of what
 * to check before using it, English plain text built from the one template
 * templates/default/tpl.privacy_draft.html and the facts of the provider.
 *
 * The template has two top-level blocks, "draft" (a {VARIABLE} per fact) and
 * "checks" (the common checks around the repeated block "specific_check"),
 * each parsed and read on its own. setVariable() does not escape: the output
 * is plain text, and the modal escapes it for HTML.
 *
 * The template object comes from an injected factory, so a unit test needs no
 * initialised ILIAS: production passes the plugin template (createDefault()),
 * a test a plain template object loaded from the same file. Production keeps
 * unknown variables, so a text in braces in a value is not removed on output
 * (a forgotten variable would show as {NAME}, which a test catches).
 */
final class ilAuthGuardPrivacyText
{
    /** @var string template file, relative to the templates folder of the plugin */
    public const TEMPLATE = "default/tpl.privacy_draft.html";

    /** @var Closure(string): object builds the template object of a template file */
    private Closure $template_factory;

    /**
     * @param Closure(string): object $template_factory gets TEMPLATE and
     *     returns a template object (HTML_Template_IT compatible) with the
     *     file loaded
     * @return void
     */
    public function __construct(Closure $template_factory)
    {
        $this->template_factory = $template_factory;
    }

    /**
     * @return self the production instance, on the template of the plugin
     */
    public static function createDefault(): self
    {
        return new self(
            static fn (string $file): object => ilAuthGuardPlugin::getInstance()->getTemplate($file, false, true)
        );
    }

    /**
     * @param ilAuthGuardPrivacyFacts $facts
     * @return string
     */
    public function getDraft(ilAuthGuardPrivacyFacts $facts): string
    {
        $tpl = $this->createTemplate();

        $tpl->setCurrentBlock("draft");
        $tpl->setVariable("NAME", $facts->name);
        $tpl->setVariable("SERVICE", $facts->service);
        $tpl->setVariable("PURPOSE", $facts->purpose);
        $tpl->setVariable("ABOUT", $facts->about);
        $tpl->setVariable("PROCESSING", $facts->processing);
        $tpl->setVariable("CONTROLLER", $facts->controller);
        $tpl->setVariable("CONSENT_SUBJECT", $facts->consent_subject);
        $tpl->setVariable("MORE_INFORMATION", $facts->more_information);
        $tpl->parseCurrentBlock();

        return trim($this->read($tpl, "draft"));
    }

    /**
     * @param ilAuthGuardPrivacyFacts $facts
     * @return string[] one entry per check, each a single line
     */
    public function getChecks(ilAuthGuardPrivacyFacts $facts): array
    {
        $tpl = $this->createTemplate();

        // An empty block is dropped: with no checks of its own, parse once.
        foreach ($facts->checks ?: [""] as $check) {
            $tpl->setCurrentBlock("specific_check");
            $tpl->setVariable("SPECIFIC_CHECK", $check);
            $tpl->parseCurrentBlock();
        }
        $tpl->setCurrentBlock("checks");
        $tpl->parseCurrentBlock();

        return array_values(array_filter(
            array_map("trim", explode("
", $this->read($tpl, "checks"))),
            static fn (string $line): bool => $line !== ""
        ));
    }

    /**
     * @return object
     */
    private function createTemplate(): object
    {
        return ($this->template_factory)(self::TEMPLATE);
    }

    /**
     * Reads a block parsed with parseCurrentBlock(). Not touchBlock(): the
     * template classes differ on whether it already parses, and parsing twice
     * repeats the text. The unmodified read keeps the plain text away from
     * the UI hook plugins, which expect page HTML.
     *
     * @param object $tpl
     * @param string $block
     * @return string
     */
    private function read(object $tpl, string $block): string
    {
        return method_exists($tpl, "getUnmodified") ? $tpl->getUnmodified($block) : $tpl->get($block);
    }
}
