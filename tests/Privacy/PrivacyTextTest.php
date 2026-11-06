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
        $this->assertFileExists(\ilAuthGuardPrivacyText::getTemplatePath());
        $this->assertDirectoryDoesNotExist(__DIR__ . "/../../templates/default/privacy");
        $this->assertSame([], glob(__DIR__ . "/../../templates/default/*.it.txt"));
        $this->assertCount(1, glob(__DIR__ . "/../../templates/default/*.txt"));
    }

    #[DataProvider("externalIds")]
    public function testNoTemplateMarkerIsLeftUnfilled(string $id): void
    {
        $text = \ilAuthGuardPrivacyText::getDraft(self::facts($id)) . "\n"
            . implode("\n", \ilAuthGuardPrivacyText::getChecks(self::facts($id)));

        $this->assertStringNotContainsString("{{", $text, $id);
        $this->assertStringNotContainsString("@@", $text, $id);
    }

    public function testAValueIsNeverScannedForMarkersAgain(): void
    {
        $facts = new \ilAuthGuardPrivacyFacts("{{ABOUT}}", "S", "P", "A{{NAME}}", "X", "C", "T", "M", ["k {{NAME}}"]);

        $this->assertStringContainsString("({{ABOUT}})", \ilAuthGuardPrivacyText::getDraft($facts));
        $this->assertStringContainsString("A{{NAME}}", \ilAuthGuardPrivacyText::getDraft($facts));
        $this->assertContains("k {{NAME}}", \ilAuthGuardPrivacyText::getChecks($facts));
    }

    #[DataProvider("externalIds")]
    public function testEveryDraftIsEnglishAndComplete(string $id): void
    {
        $text = (string) \ilAuthGuardPrivacyText::getDraft(self::facts($id));

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
        $checks = \ilAuthGuardPrivacyText::getChecks(self::facts($id));
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
        $draft = (string) \ilAuthGuardPrivacyText::getDraft(self::facts($id));
        $all = implode("\n", \ilAuthGuardPrivacyText::getChecks(self::facts($id)));
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
        $this->assertStringContainsString($needle, implode("\n", \ilAuthGuardPrivacyText::getChecks(self::facts($id))));
    }

    #[DataProvider("externalIds")]
    public function testTextsContainNoDashes(string $id): void
    {
        $text = (string) \ilAuthGuardPrivacyText::getDraft(self::facts($id)) . "\n" . implode("\n", \ilAuthGuardPrivacyText::getChecks(self::facts($id)));

        $this->assertStringNotContainsString("--", $text);
        $this->assertStringNotContainsString("\u{2014}", $text);
        $this->assertStringNotContainsString("\u{2013}", $text);
    }

    public function testHcaptchaDraftStatesTheConfirmedFacts(): void
    {
        $text = (string) \ilAuthGuardPrivacyText::getDraft(self::facts("hcaptcha"));

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
        $text = (string) \ilAuthGuardPrivacyText::getDraft(self::facts("friendlycaptcha"));

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
            "Close"
        );
        $log["components"] = $drafts->createComponents();

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
        $this->assertCount(3, $log["components"], "heading, button and modal");

        foreach (array_keys(self::externalIds()) as $id) {
            $this->assertStringContainsString("<h4>T[cfg_provider_" . $id . "]</h4>", $html, $id);
            $this->assertStringContainsString(
                htmlspecialchars((string) \ilAuthGuardPrivacyText::getDraft(self::facts($id)), ENT_QUOTES, "UTF-8"),
                $html,
                $id
            );
        }
        $this->assertStringNotContainsString("cfg_provider_altcha", $html);
        $this->assertSame(5, substr_count($html, "<textarea"));
        $this->assertSame(5, substr_count($html, "<h5>T[cfg_privacy_checks_title]</h5>"));
    }

    public function testTheModalListsTheChecksOfEachProviderInOrder(): void
    {
        $log = $this->createDrafts();

        $this->assertSame(
            array_map(static fn (string $id): array => \ilAuthGuardPrivacyText::getChecks(self::facts($id)), array_keys(self::externalIds())),
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
