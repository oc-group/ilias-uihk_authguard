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

namespace AuthGuard\Tests;

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

require_once __DIR__ . "/../PlainTemplate.php";

/**
 * The draft privacy texts of the external providers, the lists of what to
 * check, and the one modal that shows them.
 */
class PrivacyTextTest extends TestCase
{
    /**
     * @return array<string, array{0: string}>
     */
    public static function externalIds(): array
    {
        $ids = [];
        foreach (\ilAuthGuardProviderRegistry::createDefault()->all() as $id => $provider) {
            if ($provider->isExternal()) {
                $ids[$id] = [$id];
            }
        }

        return $ids;
    }

    /**
     * @return string absolute path of the templates folder of the plugin
     */
    private static function templates(): string
    {
        return __DIR__ . "/../../templates/";
    }

    /**
     * The text builder on a plain template object, loaded from the same file
     * production loads (the TEMPLATE constant).
     *
     * @return \ilAuthGuardPrivacyText
     */
    private static function text(): \ilAuthGuardPrivacyText
    {
        return new \ilAuthGuardPrivacyText(
            static fn (string $file): object => PlainTemplate::load(self::templates() . $file)
        );
    }

    /**
     * @param string $id
     * @return \ilAuthGuardPrivacyFacts
     */
    private static function facts(string $id): \ilAuthGuardPrivacyFacts
    {
        $facts = \ilAuthGuardProviderRegistry::createDefault()->find($id)?->getPrivacyFacts();
        self::assertNotNull($facts, $id);

        return $facts;
    }

    public function testEveryExternalProviderIsCovered(): void
    {
        $this->assertSame(
            ["recaptcha", "recaptcha3", "turnstile", "hcaptcha", "friendlycaptcha"],
            array_keys(self::externalIds())
        );
    }

    public function testAltchaHasNoPrivacyFacts(): void
    {
        $this->assertNull(\ilAuthGuardProviderRegistry::createDefault()->find("altcha")?->getPrivacyFacts());
    }

    public function testOnlyExternalProvidersHavePrivacyFacts(): void
    {
        foreach (\ilAuthGuardProviderRegistry::createDefault()->all() as $id => $provider) {
            $this->assertSame($provider->isExternal(), $provider->getPrivacyFacts() !== null, $id);
        }
    }

    public function testThereIsOneTemplateAndNoPerProviderFiles(): void
    {
        $this->assertSame("default/tpl.privacy_draft.html", \ilAuthGuardPrivacyText::TEMPLATE);
        $this->assertFileExists(self::templates() . \ilAuthGuardPrivacyText::TEMPLATE);
        $this->assertDirectoryDoesNotExist(self::templates() . "default/privacy");
        $this->assertSame([], glob(self::templates() . "default/*.it.txt"));
        $this->assertSame([], glob(self::templates() . "default/*.txt"), "no plain text template is left");
        $this->assertSame(
            ["tpl.privacy_draft.html"],
            array_map("basename", glob(self::templates() . "default/*privacy*"))
        );
    }

    public function testTheFactoryGetsTheTemplateFileOfTheConstant(): void
    {
        $asked = [];
        $text = new \ilAuthGuardPrivacyText(static function (string $file) use (&$asked): object {
            $asked[] = $file;

            return PlainTemplate::load(self::templates() . $file);
        });

        $text->getDraft(self::facts("turnstile"));
        $text->getChecks(self::facts("turnstile"));

        $this->assertSame([\ilAuthGuardPrivacyText::TEMPLATE, \ilAuthGuardPrivacyText::TEMPLATE], $asked);
    }

    public function testTheTemplateIsInTheIlTemplateSyntaxWithoutTheOldMarkers(): void
    {
        $template = (string) file_get_contents(self::templates() . \ilAuthGuardPrivacyText::TEMPLATE);

        $this->assertStringNotContainsString("{{", $template);
        $this->assertStringNotContainsString("@@", $template);
        foreach (["draft", "checks", "specific_check"] as $block) {
            $this->assertSame(1, substr_count($template, "<!-- BEGIN " . $block . " -->"), $block);
            $this->assertSame(1, substr_count($template, "<!-- END " . $block . " -->"), $block);
        }
        preg_match_all("/\\{([A-Z0-9_]+)\\}/", $template, $found);
        $variables = array_unique($found[1]);
        sort($variables);
        $this->assertSame(
            ["ABOUT", "CONSENT_SUBJECT", "CONTROLLER", "MORE_INFORMATION", "NAME", "PROCESSING", "PURPOSE",
                "SERVICE", "SPECIFIC_CHECK"],
            $variables
        );
    }

    #[DataProvider("externalIds")]
    public function testNoTemplateVariableIsLeftUnfilled(string $id): void
    {
        $text = self::text()->getDraft(self::facts($id)) . "\n"
            . implode("\n", self::text()->getChecks(self::facts($id)));

        $this->assertDoesNotMatchRegularExpression("/\\{[A-Z0-9_]+\\}|__[a-z_]+__|BEGIN |END |<!--/", $text, $id);
        $this->assertStringNotContainsString("@@", $text, $id);
    }

    public function testAValueIsPassedThroughUnchanged(): void
    {
        $service = "S [x] \"q\" 'a' <b> & \$1 \\1";
        $facts = new \ilAuthGuardPrivacyFacts(
            "N {X}",
            $service,
            "P",
            "A{X}{Y_Z}",
            "X",
            "C",
            "T",
            "M",
            ["k {X} {Y}", "[second]"]
        );

        $draft = self::text()->getDraft($facts);
        $this->assertStringContainsString("(N {X})", $draft);
        $this->assertStringContainsString($service, $draft);
        $this->assertStringContainsString("A{X}{Y_Z}", $draft);
        $this->assertSame("k {X} {Y}", self::text()->getChecks($facts)[1]);
        $this->assertSame("[second]", self::text()->getChecks($facts)[2]);
    }

    /**
     * The template engine replaces the variables one after the other on the
     * block text, so a value that itself held the name of a variable set
     * later, such as {ABOUT}, would be substituted. An unknown name in braces
     * is kept (see the test above). No fact has any brace, only square
     * brackets, and this keeps it so.
     */
    #[DataProvider("externalIds")]
    public function testNoFactHasABrace(string $id): void
    {
        $facts = self::facts($id);
        $all = implode("
", [$facts->name, $facts->service, $facts->purpose, $facts->about, $facts->processing,
            $facts->controller, $facts->consent_subject, $facts->more_information, ...$facts->checks]);

        $this->assertStringNotContainsString("{", $all, $id);
        $this->assertStringNotContainsString("}", $all, $id);
    }

    public function testTheChecksComeOutInTheOrderCommonSpecificCommon(): void
    {
        $facts = new \ilAuthGuardPrivacyFacts("N", "S", "P", "A", "X", "C", "T", "M", ["first specific", "second specific"]);
        $checks = self::text()->getChecks($facts);

        $this->assertCount(6, $checks);
        $this->assertStringStartsWith("Fill in the name and contact details of the data controller", $checks[0]);
        $this->assertSame("first specific", $checks[1]);
        $this->assertSame("second specific", $checks[2]);
        $this->assertStringStartsWith("Decide with the data protection officer", $checks[3]);
        $this->assertStringStartsWith("Translate the draft", $checks[4]);
        $this->assertStringStartsWith("Check the vendor's own privacy documents", $checks[5]);
    }

    public function testWithoutSpecificChecksOnlyTheFourCommonOnesRemain(): void
    {
        $checks = self::text()->getChecks(new \ilAuthGuardPrivacyFacts("N", "S", "P", "A", "X", "C", "T", "M"));

        $this->assertCount(4, $checks);
    }

    public function testTheDraftKeepsItsParagraphBreaksAndHasNoSurroundingBlankLines(): void
    {
        $draft = self::text()->getDraft(new \ilAuthGuardPrivacyFacts("N", "S", "P", "A", "X", "C", "T", "M"));

        $this->assertSame(
            "Protection of forms against automated abuse (N)\n\n"
            . "This website uses S on its forms to P, and so to protect the website and its users against spam and abuse. A\n\n"
            . "X\n\n"
            . "Data controller: [name and contact details of the controller]. C\n\n"
            . "Legal basis: Art. 6(1)(f) GDPR, our legitimate interest in the security of the website and in blocking abusive use. "
            . "[To be settled by the data protection officer: whether consent is required under the ePrivacy rules for T; "
            . "adapt this paragraph accordingly.]\n\n"
            . "More information: M",
            $draft
        );
    }

    /**
     * @return array<string, array{0: string, 1: bool, 2: bool}>
     */
    public static function optionalNotes(): array
    {
        return [
            "recaptcha3" => ["recaptcha3", true, false],
            "friendlycaptcha" => ["friendlycaptcha", false, true],
            "turnstile" => ["turnstile", false, false],
            "hcaptcha" => ["hcaptcha", false, false],
            "recaptcha" => ["recaptcha", false, false],
        ];
    }

    #[DataProvider("optionalNotes")]
    public function testTheOptionalNotesAppearOnlyForTheProvidersThatUseThem(string $id, bool $badge, bool $eu): void
    {
        $text = self::text()->getDraft(self::facts($id));

        $this->assertSame($badge, str_contains($text, "[If the reCAPTCHA badge is hidden"), $id);
        $this->assertSame($eu, str_contains($text, "[If the EU endpoint is selected"), $id);
    }

    #[DataProvider("externalIds")]
    public function testEveryDraftIsEnglishAndComplete(string $id): void
    {
        $text = (string) self::text()->getDraft(self::facts($id));

        $this->assertGreaterThan(120, str_word_count($text), $id);
        $this->assertStringContainsString("This website uses", $text);
        $this->assertStringContainsString("Art. 6(1)(f) GDPR", $text);
        $this->assertStringContainsString("[name and contact details of the controller]", $text);
        $this->assertStringContainsString("ePrivacy", $text);
        $this->assertStringContainsString("data protection officer", $text);
        $this->assertStringNotContainsString("Questo sito", $text);
    }

    #[DataProvider("externalIds")]
    public function testEveryProviderHasAListOfWhatToCheck(string $id): void
    {
        $checks = self::text()->getChecks(self::facts($id));
        $all = implode("\n", $checks);

        $this->assertGreaterThanOrEqual(7, count($checks), $id);
        $this->assertStringContainsString("name and contact details of the data controller", $all);
        $this->assertStringContainsString("ePrivacy", $all);
        $this->assertStringContainsString("cookie banner", $all);
        $this->assertStringContainsString("Translate the draft into the language of the privacy policy", $all);
        $this->assertSame(array_values(array_unique($checks)), $checks, "no duplicate item");
    }

    #[DataProvider("externalIds")]
    public function testEveryBracketedPlaceholderOfADraftIsMirroredInTheChecks(string $id): void
    {
        $draft = (string) self::text()->getDraft(self::facts($id));
        $all = implode("\n", self::text()->getChecks(self::facts($id)));
        preg_match_all("/\\[([^\\]]+)\\]/", $draft, $matches);

        $this->assertNotEmpty($matches[1]);
        foreach ($matches[1] as $placeholder) {
            $mirrored = str_contains($all, "[" . rtrim($placeholder, ".") . "")
                || str_starts_with($placeholder, "name and contact")
                || str_contains($placeholder, "ePrivacy")
                || str_contains($placeholder, "EU endpoint")
                || str_contains($placeholder, "Data processing agreement")
                || str_contains($placeholder, "badge")
                || str_contains($placeholder, "country of the vendor")
                || str_contains($placeholder, "Location of the processing");
            $this->assertTrue($mirrored, $id . ": " . $placeholder);
        }
    }

    /**
     * @return array<string, array{0: string, 1: string}>
     */
    public static function specificChecks(): array
    {
        return [
            "recaptcha DPA" => ["recaptcha", "Google Cloud Data Processing Addendum"],
            "recaptcha entity" => ["recaptcha", "[Google legal entity and country"],
            "recaptcha location" => ["recaptcha", "[Location of the processing and transfers outside the EU"],
            "recaptcha link" => ["recaptcha", "[link to the Google privacy information for reCAPTCHA]"],
            "recaptcha3 DPA" => ["recaptcha3", "Google Cloud Data Processing Addendum"],
            "recaptcha3 badge" => ["recaptcha3", "This site is protected by reCAPTCHA."],
            "turnstile DPA" => ["turnstile", "Cloudflare Customer DPA"],
            "turnstile country" => ["turnstile", "[country of the vendor"],
            "turnstile location" => ["turnstile", "[Location of the processing: to be completed.]"],
            "hcaptcha DPA" => ["hcaptcha", "data processing addendum is incorporated in the hCaptcha terms"],
            "hcaptcha basis" => ["hcaptcha", "Art. 6(1)(b)"],
            "friendly DPA" => ["friendlycaptcha", "Request the data processing agreement from Friendly Captcha"],
            "friendly endpoint" => ["friendlycaptcha", "only if the EU endpoint is selected in the AuthGuard settings"],
        ];
    }

    #[DataProvider("specificChecks")]
    public function testProviderSpecificChecks(string $id, string $needle): void
    {
        $this->assertStringContainsString($needle, implode("\n", self::text()->getChecks(self::facts($id))));
    }

    #[DataProvider("externalIds")]
    public function testTextsContainNoDashes(string $id): void
    {
        $text = (string) self::text()->getDraft(self::facts($id)) . "\n" . implode("\n", self::text()->getChecks(self::facts($id)));

        $this->assertStringNotContainsString("--", $text);
        $this->assertStringNotContainsString("\u{2014}", $text);
        $this->assertStringNotContainsString("\u{2013}", $text);
    }

    public function testHcaptchaDraftStatesTheConfirmedFacts(): void
    {
        $text = (string) self::text()->getDraft(self::facts("hcaptcha"));

        foreach (
            ["Intuition Machines, Inc.", "Delaware", "data processor", "standard contractual clauses",
                "EU-U.S. Data Privacy Framework", "United States", "mouse movements",
                "https://www.hcaptcha.com/privacy"] as $fact
        ) {
            $this->assertStringContainsString($fact, $text);
        }
    }

    public function testFriendlyCaptchaDraftStatesTheConfirmedFacts(): void
    {
        $text = (string) self::text()->getDraft(self::facts("friendlycaptcha"));

        foreach (
            ["Friendly Captcha GmbH, Germany", "data processor", "European Union", "one-way hash", "no HTTP cookies"] as $fact
        ) {
            $this->assertStringContainsString($fact, $text);
        }
    }

    public function testTheControlHasLangKeysInBothLanguages(): void
    {
        foreach (["en", "it"] as $language) {
            $file = "\n" . (string) file_get_contents(__DIR__ . "/../../lang/ilias_" . $language . ".lang");
            foreach (
                ["cfg_privacy_draft_label", "cfg_privacy_draft_notice", "cfg_privacy_draft_show",
                    "cfg_privacy_drafts_intro", "cfg_privacy_drafts_title", "cfg_privacy_checks_title"] as $key
            ) {
                $this->assertStringContainsString("\n" . $key . "#:#", $file, $language . ": " . $key);
            }
        }
    }

    public function testBothLanguageFilesHaveTheSameKeys(): void
    {
        $keys = static fn (string $language): array => array_map(
            static fn (string $line): string => explode("#:#", $line)[0],
            file(__DIR__ . "/../../lang/ilias_" . $language . ".lang", FILE_IGNORE_NEW_LINES)
        );

        $this->assertSame($keys("en"), $keys("it"));
    }

    public function testTheModalNoticeWarnsThatTheDraftIsNotLegalAdvice(): void
    {
        $en = (string) file_get_contents(__DIR__ . "/../../lang/ilias_en.lang");
        $it = (string) file_get_contents(__DIR__ . "/../../lang/ilias_it.lang");

        $this->assertMatchesRegularExpression("/cfg_privacy_draft_notice#:#.*not legal advice.*placeholders/", $en);
        $this->assertMatchesRegularExpression("/cfg_privacy_draft_notice#:#.*non costituisce consulenza legale/i", $it);
        $this->assertStringContainsString("Administration > Legal Regulations > Declaration of Data Protection", $en);
        $this->assertStringContainsString("The drafts are in English", $en);
        $this->assertStringContainsString("Le bozze sono in inglese", $it);
    }

    /**
     * Builds the drafts with a recording stand-in for the UI factory.
     *
     * @return array{components: array<int, object>, roundtrips: array<int, array{0: string, 1: array<int, object>}>,
     *     html: string[], lists: array<int, string[]>, buttons: array<int, string>, close: string[]}
     */
    private function createDrafts(): array
    {
        $log = ["roundtrips" => [], "html" => [], "lists" => [], "buttons" => [], "close" => []];

        $legacy = $this->createMock(\ILIAS\UI\Component\Legacy\Factory::class);
        $legacy->method("content")->willReturnCallback(function (string $html) use (&$log) {
            $log["html"][] = $html;

            return $this->createMock(\ILIAS\UI\Component\Legacy\Content::class);
        });
        $message_box = $this->createMock(\ILIAS\UI\Component\MessageBox\Factory::class);
        $message_box->method("info")->willReturn($this->createMock(\ILIAS\UI\Component\MessageBox\MessageBox::class));
        $listing = $this->createMock(\ILIAS\UI\Component\Listing\Factory::class);
        $listing->method("unordered")->willReturnCallback(function (array $items) use (&$log) {
            $log["lists"][] = $items;

            return $this->createMock(\ILIAS\UI\Component\Listing\Unordered::class);
        });
        $signal = $this->createMock(\ILIAS\UI\Component\Signal::class);
        $modal = $this->createMock(\ILIAS\UI\Component\Modal\RoundTrip::class);
        $modal->method("withCancelButtonLabel")->willReturnCallback(function (string $label) use (&$log, $modal) {
            $log["close"][] = $label;

            return $modal;
        });
        $modal->method("getShowSignal")->willReturn($signal);
        $modals = $this->createMock(\ILIAS\UI\Component\Modal\Factory::class);
        $modals->method("roundtrip")->willReturnCallback(function (string $title, $content) use (&$log, $modal) {
            $log["roundtrips"][] = [$title, $content];

            return $modal;
        });
        $buttons = $this->createMock(\ILIAS\UI\Component\Button\Factory::class);
        $buttons->method("standard")->willReturnCallback(function (string $label, $action) use (&$log, $signal) {
            $this->assertSame($signal, $action);
            $log["buttons"][] = $label;

            return $this->createMock(\ILIAS\UI\Component\Button\Standard::class);
        });

        $ui = $this->createMock(\ILIAS\UI\Factory::class);
        $ui->method("legacy")->willReturn($legacy);
        $ui->method("messageBox")->willReturn($message_box);
        $ui->method("listing")->willReturn($listing);
        $ui->method("modal")->willReturn($modals);
        $ui->method("button")->willReturn($buttons);

        $drafts = new \ilAuthGuardPrivacyDrafts(
            $ui,
            \ilAuthGuardProviderRegistry::createDefault(),
            static fn (string $key): string => "T[" . $key . "]",
            "Close",
            self::text()
        );
        $log["components"] = [$drafts->createButton(), $drafts->createModal()];

        return $log;
    }

    public function testOneModalHoldsEveryExternalProviderAndAltchaHasNone(): void
    {
        $log = $this->createDrafts();
        $html = implode("\n", $log["html"]);

        $this->assertCount(1, $log["roundtrips"]);
        $this->assertSame("T[cfg_privacy_drafts_title]", $log["roundtrips"][0][0]);
        $this->assertCount(1, $log["buttons"]);
        $this->assertSame("T[cfg_privacy_draft_show]", $log["buttons"][0]);
        $this->assertSame(["Close"], $log["close"]);
        $this->assertCount(2, $log["components"], "button and modal");
        $this->assertNotNull($log["components"][0]);

        foreach (array_keys(self::externalIds()) as $id) {
            $this->assertStringContainsString("<h4>T[cfg_provider_" . $id . "]</h4>", $html, $id);
            $this->assertStringContainsString(
                htmlspecialchars((string) self::text()->getDraft(self::facts($id)), ENT_QUOTES, "UTF-8"),
                $html,
                $id
            );
        }
        $this->assertStringNotContainsString("cfg_provider_altcha", $html);
        $this->assertSame(5, substr_count($html, '<pre class="ilAuthGuardDraft" role="region" tabindex="0"'));
        $this->assertSame(5, substr_count($html, ' aria-label="T[cfg_privacy_draft_label]">'));
        $this->assertSame(5, substr_count($html, "</pre>"));
        $this->assertStringNotContainsString("<textarea", $html);
        $this->assertStringNotContainsString("onfocus", $html);
        $this->assertSame(5, substr_count($html, "<h5>T[cfg_privacy_checks_title]</h5>"));
    }

    public function testTheModalListsTheChecksOfEachProviderInOrder(): void
    {
        $log = $this->createDrafts();

        $this->assertSame(
            array_map(static fn (string $id): array => self::text()->getChecks(self::facts($id)), array_keys(self::externalIds())),
            $log["lists"]
        );
    }

    public function testTheModalContentStartsWithTheNoticeAndTheIntro(): void
    {
        $log = $this->createDrafts();
        $content = $log["roundtrips"][0][1];

        $this->assertInstanceOf(\ILIAS\UI\Component\MessageBox\MessageBox::class, $content[0]);
        $this->assertStringContainsString("T[cfg_privacy_drafts_intro]", $log["html"][0]);
        $this->assertCount(2 + 2 * 5, $content);
    }

    public function testTheDraftsAreEscapedInTheTextArea(): void
    {
        $log = $this->createDrafts();
        $html = implode("\n", $log["html"]);

        $this->assertStringNotContainsString("(\"hCaptcha\")", $html);
        $this->assertStringContainsString("(&quot;hCaptcha&quot;)", $html);
    }
}
