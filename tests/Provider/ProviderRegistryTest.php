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

require_once __DIR__ . "/../ArraySessionStore.php";
require_once __DIR__ . "/../SettingsFixture.php";

/**
 * The registry, the settings of every provider (storage, legacy keys,
 * validation) and the consistency of each provider with the template and
 * the language files.
 */
class ProviderRegistryTest extends TestCase
{
    use SettingsFixture;

    private const GOOGLE_SITE_KEY = "6LeIxAcTAAAAAJcZVRqyHh71UMIEGNQ_MXjiZKhI";

    private const GOOGLE_SECRET = "6LeIxAcTAAAAAGG-vFI1TnRWxMZNFuojJ4WifJWe";

    private \ilAuthGuardProviderRegistry $registry;

    /**
     * @return array<string, array{0: string}>
     */
    public static function providerIds(): array
    {
        $ids = [];
        foreach (\ilAuthGuardProviderRegistry::getKnownIds() as $id) {
            $ids[$id] = [$id];
        }

        return $ids;
    }

    protected function setUp(): void
    {
        $this->registry = \ilAuthGuardProviderRegistry::createDefault();
    }

    public function testTheProvidersInDisplayOrder(): void
    {
        $this->assertSame(
            ["altcha", "recaptcha", "recaptcha3", "turnstile", "hcaptcha", "friendlycaptcha"],
            array_keys($this->registry->all())
        );
        $this->assertSame(\ilAuthGuardProviderRegistry::getKnownIds(), array_keys($this->registry->all()));
    }

    public function testAltchaIsTheDefault(): void
    {
        $this->assertSame("altcha", $this->registry->getDefault()->getId());
        $this->assertSame("altcha", \ilAuthGuardProviderRegistry::DEFAULT_ID);
    }

    public function testOnlyAltchaStaysOnThisServer(): void
    {
        foreach ($this->registry->all() as $id => $provider) {
            $this->assertSame($id !== "altcha", $provider->isExternal(), $id);
        }
    }

    public function testEveryIdIsLowercaseLettersAndDigits(): void
    {
        foreach (\ilAuthGuardProviderRegistry::getKnownIds() as $id) {
            $this->assertMatchesRegularExpression("/^[a-z][a-z0-9]*$/D", $id);
        }
    }

    public function testEveryProviderPostsToAFieldOfItsOwn(): void
    {
        $fields = array_map(
            static fn (\ilAuthGuardChallengeProvider $p): string => $p->getPostField(),
            $this->registry->all()
        );

        $this->assertSame(array_values(array_unique($fields)), array_values($fields));
        $this->assertSame("authguard_pow", $fields["altcha"]);
        $this->assertSame("g-recaptcha-response", $fields["recaptcha"]);
        $this->assertSame("authguard_recaptcha3", $fields["recaptcha3"]);
        $this->assertSame("cf-turnstile-response", $fields["turnstile"]);
        $this->assertSame("h-captcha-response", $fields["hcaptcha"]);
        $this->assertSame("frc-captcha-response", $fields["friendlycaptcha"]);
    }

    public function testEveryProviderFailsWithADistinctReason(): void
    {
        $reasons = array_map(
            static fn (\ilAuthGuardChallengeProvider $p): string => $p->getFailureReason(),
            $this->registry->all()
        );

        $this->assertSame(array_values(array_unique($reasons)), array_values($reasons));
        $this->assertSame("pow", $reasons["altcha"]);
        $this->assertSame("recaptcha", $reasons["recaptcha"]);
    }

    public function testNoTwoProvidersShareATemplateVariable(): void
    {
        $seen = [];
        foreach ($this->registry->all() as $id => $provider) {
            foreach ($provider->getBlockVariables() as $name) {
                $this->assertArrayNotHasKey($name, $seen, $name . " of " . $id);
                $seen[$name] = $id;
            }
        }
    }

    public function testUnknownIdIsNotFound(): void
    {
        $this->assertNull($this->registry->find("nope"));
        $this->assertFalse(\ilAuthGuardProviderRegistry::isKnownId("nope"));
        $this->assertTrue(\ilAuthGuardProviderRegistry::isKnownId("hcaptcha"));
    }

    #[DataProvider("providerIds")]
    public function testEveryProviderHasABlockInTheTemplateWithExactlyItsVariables(string $id): void
    {
        $template = (string) file_get_contents(__DIR__ . "/../../templates/default/tpl.form_protection.html");

        $this->assertSame(1, preg_match("/<!-- BEGIN " . $id . " -->(.*?)<!-- END " . $id . " -->/s", $template, $m), $id);
        preg_match_all("/\\{([A-Z0-9_]+)\\}/", $m[1], $found);
        $in_template = array_unique($found[1]);
        $declared = $this->registry->find($id)->getBlockVariables();

        sort($in_template);
        sort($declared);
        $this->assertSame($declared, $in_template, $id);
    }

    #[DataProvider("providerIds")]
    public function testEveryLangKeyOfAProviderExistsInBothLanguages(string $id): void
    {
        $provider = $this->registry->find($id);
        $keys = ["cfg_provider_" . $id, "cfg_provider_" . $id . "_info"];
        foreach ($provider->getSettingsFields() as $field) {
            $keys[] = $field->label_key;
            $keys[] = $field->error_key;
            if ($field->info_key !== "") {
                $keys[] = $field->info_key;
            }
            foreach ($field->options as $option_key) {
                $keys[] = $option_key;
            }
        }

        foreach (["en", "it"] as $language) {
            $file = (string) file_get_contents(__DIR__ . "/../../lang/ilias_" . $language . ".lang");
            foreach ($keys as $key) {
                $this->assertStringContainsString("\n" . $key . "#:#", "\n" . $file, $language . ": " . $key);
            }
        }
    }

    public function testNoLangValueContainsADash(): void
    {
        foreach (["en", "it"] as $language) {
            foreach (file(__DIR__ . "/../../lang/ilias_" . $language . ".lang", FILE_IGNORE_NEW_LINES) as $line) {
                $value = explode("#:#", $line, 2)[1];
                $this->assertStringNotContainsString("--", $value, $line);
                $this->assertStringNotContainsString("\u{2014}", $value, $line);
                $this->assertStringNotContainsString("\u{2013}", $value, $line);
            }
        }
    }

    #[DataProvider("providerIds")]
    public function testStoredSecretsAreEncryptedAndReadBack(string $id): void
    {
        $settings = $this->makeSettings();
        $provider = $this->registry->find($id);

        if ($id === "altcha") {
            $this->assertSame([], $provider->getSettingsFields());

            return;
        }

        foreach ($provider->getSettingsFields() as $field) {
            if (!$field->isSecret()) {
                continue;
            }

            $settings->setProviderSecret($id, $field->name, "plain-secret-value-123456");
            $stored = $this->rows[$id . "_" . $field->name];

            $this->assertStringStartsWith("v1:", $stored);
            $this->assertStringNotContainsString("plain-secret-value-123456", $stored);
            $this->assertSame("plain-secret-value-123456", $settings->getProviderSecret($id, $field->name));
            $this->assertTrue($settings->hasProviderSecret($id, $field->name));

            $settings->setProviderSecret($id, $field->name, "");
            $this->assertSame($stored, $this->rows[$id . "_" . $field->name]);
        }
    }

    #[DataProvider("providerIds")]
    public function testAProviderIsConfiguredOnlyWithEveryRequiredSetting(string $id): void
    {
        $settings = $this->makeSettings();
        $provider = $this->registry->find($id);

        if ($id === "altcha") {
            $this->assertTrue($provider->isConfigured($settings));

            return;
        }

        $this->assertFalse($provider->isConfigured($settings));
        $settings->setProviderValue($id, "site_key", "KEY");
        $this->assertFalse($provider->isConfigured($settings));
        foreach ($provider->getSettingsFields() as $field) {
            if ($field->isSecret()) {
                $settings->setProviderSecret($id, $field->name, "plain-secret-value-123456");
            }
        }
        $this->assertTrue($provider->isConfigured($settings));
    }

    #[DataProvider("providerIds")]
    public function testEveryProviderIsSelectableAndEffectiveOnceConfigured(string $id): void
    {
        $settings = $this->makeSettings();
        $settings->setProvider($id);
        $this->assertSame($id, $settings->getProvider());

        if ($id === "altcha") {
            $this->assertSame("altcha", $settings->getEffectiveProvider());

            return;
        }

        $this->assertSame("altcha", $settings->getEffectiveProvider());
        $settings->setProviderValue($id, "site_key", "KEY");
        foreach ($this->registry->find($id)->getSettingsFields() as $field) {
            if ($field->isSecret()) {
                $settings->setProviderSecret($id, $field->name, "plain-secret-value-123456");
            }
        }
        $this->assertSame($id, $settings->getEffectiveProvider());
        $this->assertSame($id, $this->registry->resolve($settings)->getId());
    }

    public function testSettingsWrittenByTheVersionsBeforeProvidersKeepWorking(): void
    {
        // The rows a 11.1.2 installation holds: provider, recaptcha_site_key and a "v1:" secret.
        $writer = $this->makeSettings();
        $writer->setProviderSecret("recaptcha", "secret_key", self::GOOGLE_SECRET);
        $legacy_secret = $this->rows["recaptcha_secret_key"];
        $this->rows = [
            "provider" => "recaptcha",
            "recaptcha_site_key" => self::GOOGLE_SITE_KEY,
            "recaptcha_secret_key" => $legacy_secret,
        ];

        $settings = new \ilAuthGuardSettings($this->makeStore(), $this->makeStorage());

        $this->assertSame("recaptcha", $settings->getProvider());
        $this->assertSame("recaptcha", $settings->getEffectiveProvider());
        $this->assertSame(self::GOOGLE_SITE_KEY, $settings->getProviderValue("recaptcha", "site_key"));
        $this->assertSame(self::GOOGLE_SECRET, $settings->getProviderSecret("recaptcha", "secret_key"));
        $this->assertSame("recaptcha_site_key", (new \ilAuthGuardProviderRecaptcha())->getSettingsFields()[0]->getPostVar("recaptcha"));
    }

    public function testTheStorageKeyOfEachSettingIsProviderUnderscoreField(): void
    {
        $settings = $this->makeSettings();
        $settings->setProviderValue("friendlycaptcha", "endpoint", "eu");
        $settings->setProviderValue("recaptcha3", "threshold", "0.7");
        $settings->setProviderSecret("friendlycaptcha", "api_key", "plain-secret-value-123456");

        $this->assertSame("eu", $this->rows["friendlycaptcha_endpoint"]);
        $this->assertSame("0.7", $this->rows["recaptcha3_threshold"]);
        $this->assertArrayHasKey("friendlycaptcha_api_key", $this->rows);
    }

    public function testReCaptchaV2AndV3KeepSeparateKeys(): void
    {
        $settings = $this->makeSettings();
        $settings->setProviderValue("recaptcha", "site_key", "V2-KEY");
        $settings->setProviderValue("recaptcha3", "site_key", "V3-KEY");

        $this->assertSame("V2-KEY", $settings->getProviderValue("recaptcha", "site_key"));
        $this->assertSame("V3-KEY", $settings->getProviderValue("recaptcha3", "site_key"));
    }

    public function testAnUnknownStoredProviderReadsAsAltcha(): void
    {
        $this->rows["provider"] = "recaptcha4";

        $this->assertSame("altcha", $this->makeSettings()->getProvider());
    }

    public function testAnUnknownProviderCannotBeStored(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->makeSettings()->setProvider("recaptcha4");
    }

    public function testAnUnknownChoiceIsRefusedByTheValidation(): void
    {
        $this->assertSame(["provider" => "cfg_err_provider"], $this->registry->validate("nope", [], []));
    }

    public function testAltchaNeedsNothing(): void
    {
        $this->assertSame([], $this->registry->validate("altcha", [], []));
    }

    /**
     * @return array<string, array{0: string, 1: array<string, string>, 2: bool}>
     */
    public static function validSubmissions(): array
    {
        $uuid = "10000000-ffff-ffff-ffff-000000000001";
        $secret = "test-hcaptcha-secret-not-real";

        return [
            "recaptcha" => ["recaptcha", ["site_key" => self::GOOGLE_SITE_KEY, "secret_key" => self::GOOGLE_SECRET], false],
            "recaptcha3" => ["recaptcha3", [
                "site_key" => self::GOOGLE_SITE_KEY, "secret_key" => self::GOOGLE_SECRET, "threshold" => "0.5",
            ], false],
            "turnstile" => ["turnstile", [
                "site_key" => "0x4AAAAAAAxxxxxxxxxxxxxx", "secret_key" => "0x4AAAAAAAyyyyyyyyyyyyyyyyyyyyyyyyyyy",
            ], false],
            "hcaptcha" => ["hcaptcha", ["site_key" => $uuid, "secret_key" => $secret], false],
            "friendlycaptcha" => ["friendlycaptcha", [
                "site_key" => "FCMGEMUD2KTDSQ5H", "api_key" => "A1B2C3D4E5F6G7H8I9J0K1L2M3N4O5P6", "endpoint" => "eu",
            ], false],
        ];
    }

    /**
     * @param array<string, string> $values
     */
    #[DataProvider("validSubmissions")]
    public function testAValidSubmissionIsAccepted(string $id, array $values, bool $stored): void
    {
        $this->assertSame([], $this->registry->validate($id, $values, []));
    }

    /**
     * @param array<string, string> $values
     */
    #[DataProvider("validSubmissions")]
    public function testAnEmptySecretIsAcceptedOnlyWhenOneIsStored(string $id, array $values, bool $stored): void
    {
        $secret = $id === "friendlycaptcha" ? "api_key" : "secret_key";
        $values[$secret] = "";

        $this->assertSame(
            [$id . "_" . $secret => $this->registry->find($id)->getSettingsFields()[1]->error_key],
            $this->registry->validate($id, $values, [$secret => false])
        );
        $this->assertSame([], $this->registry->validate($id, $values, [$secret => true]));
    }

    /**
     * @param array<string, string> $values
     */
    #[DataProvider("validSubmissions")]
    public function testAMissingOrMalformedSiteKeyIsRefused(string $id, array $values, bool $stored): void
    {
        $error_key = $this->registry->find($id)->getSettingsFields()[0]->error_key;

        foreach (["", "short", $values["site_key"] . "\n", "has space and \"quotes\" 0123456789"] as $bad) {
            $values["site_key"] = $bad;
            $this->assertSame(
                [$id . "_site_key" => $error_key],
                $this->registry->validate($id, $values, ["secret_key" => true, "api_key" => true]),
                $id . ": " . json_encode($bad)
            );
        }
    }

    /**
     * @param array<string, string> $values
     */
    #[DataProvider("validSubmissions")]
    public function testAMalformedSecretIsRefused(string $id, array $values, bool $stored): void
    {
        $secret = $id === "friendlycaptcha" ? "api_key" : "secret_key";
        $values[$secret] = "has space and \"quotes\" 0123456789";

        $this->assertArrayHasKey($id . "_" . $secret, $this->registry->validate($id, $values, [$secret => true]));
    }

    public function testGoogleKeysKeepTheirExistingMessages(): void
    {
        $errors = $this->registry->validate("recaptcha", ["site_key" => "", "secret_key" => ""], ["secret_key" => false]);

        $this->assertSame(
            ["recaptcha_site_key" => "cfg_err_site_key", "recaptcha_secret_key" => "cfg_err_secret_key"],
            $errors
        );
    }

    public function testHcaptchaWantsAUuidAsSiteKey(): void
    {
        $values = ["site_key" => self::GOOGLE_SITE_KEY, "secret_key" => "test-hcaptcha-secret-not-real"];

        $this->assertSame(
            ["hcaptcha_site_key" => "cfg_err_hcaptcha_site_key"],
            $this->registry->validate("hcaptcha", $values, [])
        );
    }

    /**
     * @return array<string, array{0: string, 1: bool}>
     */
    public static function thresholds(): array
    {
        return [
            "zero" => ["0", true], "half" => ["0.5", true], "two decimals" => ["0.75", true], "one" => ["1", true],
            "one point zero" => ["1.0", true], "empty" => ["", false], "comma" => ["0,5", false],
            "above one" => ["1.5", false], "negative" => ["-0.1", false], "three decimals" => ["0.555", false],
            "text" => ["high", false], "trailing newline" => ["0.5\n", false],
        ];
    }

    #[DataProvider("thresholds")]
    public function testTheThresholdMustBeAScoreFromZeroToOne(string $threshold, bool $valid): void
    {
        $errors = $this->registry->validate("recaptcha3", [
            "site_key" => self::GOOGLE_SITE_KEY, "secret_key" => self::GOOGLE_SECRET, "threshold" => $threshold,
        ], []);

        $this->assertSame($valid ? [] : ["recaptcha3_threshold" => "cfg_err_threshold"], $errors, $threshold);
    }

    public function testTheThresholdDefaultsToHalf(): void
    {
        $this->assertSame(0.5, \ilAuthGuardProviderRecaptcha3::readThreshold($this->makeSettings()));
        $this->assertSame("0.5", $this->registry->find("recaptcha3")->getSettingsFields()[2]->default);
    }

    public function testFriendlyCaptchaRefusesAnUnknownEndpoint(): void
    {
        $values = ["site_key" => "FCMGEMUD2KTDSQ5H", "api_key" => "A1B2C3D4E5F6G7H8I9J0K1L2", "endpoint" => "us"];

        $this->assertSame(
            ["friendlycaptcha_endpoint" => "cfg_err_endpoint"],
            $this->registry->validate("friendlycaptcha", $values, [])
        );
    }

    public function testExternalProviderHandsAnswerAndFormIdToItsVerifier(): void
    {
        $verifier = $this->createMock(\ilAuthGuardTurnstile::class);
        $verifier->expects($this->once())->method("verify")->with("the-answer", "contact")->willReturn(true);
        $verifier->method("wasUnreachable")->willReturn(false);
        $provider = new \ilAuthGuardProviderTurnstile($verifier);

        $this->assertSame("passed", $provider->check("the-answer", $this->context("contact")));
    }

    public function testTheRenderVariablesOfAnExternalProviderAreItsBlockVariables(): void
    {
        $settings = $this->makeSettings();
        $settings->setProviderValue("friendlycaptcha", "site_key", "FCMGEMUD2KTDSQ5H");
        $settings->setProviderValue("friendlycaptcha", "endpoint", "eu");
        $provider = new \ilAuthGuardProviderFriendlyCaptcha();

        $vars = $provider->getRenderVariables($this->context("contact", $settings));

        $this->assertSame(
            ["FRIENDLYCAPTCHA_SITE_KEY", "FRIENDLYCAPTCHA_SCRIPT_URL", "FRIENDLYCAPTCHA_ENDPOINT"],
            array_keys($vars)
        );
        $this->assertSame("FCMGEMUD2KTDSQ5H", $vars["FRIENDLYCAPTCHA_SITE_KEY"]);
        $this->assertSame("eu", $vars["FRIENDLYCAPTCHA_ENDPOINT"]);
        $this->assertSame("asset/js/authguard-friendlycaptcha.js", $vars["FRIENDLYCAPTCHA_SCRIPT_URL"]);
        $this->assertEqualsCanonicalizing($provider->getBlockVariables(), array_keys($vars));
    }

    public function testFriendlyCaptchaRendersGlobalForAStoredUnknownEndpoint(): void
    {
        $settings = $this->makeSettings();
        $settings->setProviderValue("friendlycaptcha", "endpoint", "mars");

        $vars = (new \ilAuthGuardProviderFriendlyCaptcha())->getRenderVariables($this->context("f", $settings));

        $this->assertSame("global", $vars["FRIENDLYCAPTCHA_ENDPOINT"]);
    }

    public function testRecaptcha3RendersTheActionOfTheForm(): void
    {
        $vars = (new \ilAuthGuardProviderRecaptcha3())->getRenderVariables($this->context("my-form"));

        $this->assertSame("authguard_my_form", $vars["RECAPTCHA3_ACTION"]);
        $this->assertSame("authguard_recaptcha3", $vars["RECAPTCHA3_FIELD"]);
    }

    private function context(string $form_id, ?\ilAuthGuardSettings $settings = null): \ilAuthGuardProviderContext
    {
        return new \ilAuthGuardProviderContext(
            $settings ?? $this->makeSettings(),
            $this->createMock(\ilLogger::class),
            new \ilAuthGuardFormState(new ArraySessionStore(), $form_id),
            static fn (string $command): string => "url/" . $command,
            static fn (string $path): string => "asset" . $path
        );
    }

    public function testTheUnreachableChoiceIsOffByDefaultAndRoundTrips(): void
    {
        $settings = $this->makeSettings();
        $this->assertFalse($settings->isAcceptWhenUnreachable());
        $this->assertArrayNotHasKey("accept_when_unreachable", $this->rows);

        $settings->setAcceptWhenUnreachable(true);
        $this->assertTrue($settings->isAcceptWhenUnreachable());
        $this->assertSame("1", $this->rows["accept_when_unreachable"]);

        $settings->setAcceptWhenUnreachable(false);
        $this->assertFalse($settings->isAcceptWhenUnreachable());
        $this->assertSame("0", $this->rows["accept_when_unreachable"]);
    }

    public function testAnUnexpectedStoredValueOfTheUnreachableChoiceReadsAsOff(): void
    {
        $this->rows["accept_when_unreachable"] = "yes";

        $this->assertFalse($this->makeSettings()->isAcceptWhenUnreachable());
    }

    public function testTheUnreachableChoiceSurvivesDeleteAllAsOff(): void
    {
        $settings = $this->makeSettings();
        $settings->setAcceptWhenUnreachable(true);
        $settings->deleteAll();

        $this->assertFalse($settings->isAcceptWhenUnreachable());
    }

    public function testTheUnreachableChoiceHasLangKeysInBothLanguages(): void
    {
        foreach (["en", "it"] as $language) {
            $file = "\n" . (string) file_get_contents(__DIR__ . "/../../lang/ilias_" . $language . ".lang");
            $this->assertStringContainsString("\ncfg_accept_unreachable#:#", $file, $language);
            $this->assertStringContainsString("\ncfg_accept_unreachable_info#:#", $file, $language);
        }
    }
}
