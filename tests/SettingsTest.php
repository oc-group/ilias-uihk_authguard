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

use PHPUnit\Framework\TestCase;

require_once __DIR__ . "/SettingsFixture.php";

class SettingsTest extends TestCase
{
    use SettingsFixture;

    private const SITE_KEY = "6LeIxAcTAAAAAJcZVRqyHh71UMIEGNQ_MXjiZKhI";

    private const SECRET_KEY = "6LeIxAcTAAAAAGG-vFI1TnRWxMZNFuojJ4WifJWe";

    private \ilAuthGuardSettings $settings;

    protected function setUp(): void
    {
        $this->settings = $this->makeSettings();
    }

    public function testDefaultsOfAnEmptyStore(): void
    {
        $this->assertSame(\ilAuthGuardSettings::PROVIDER_ALTCHA, $this->settings->getProvider());
        $this->assertSame(\ilAuthGuardSettings::PROVIDER_ALTCHA, $this->settings->getEffectiveProvider());
        $this->assertSame("", $this->settings->getRecaptchaSiteKey());
        $this->assertFalse($this->settings->hasRecaptchaSecretKey());
        $this->assertSame("", $this->settings->getRecaptchaSecretKey());
        $this->assertFalse($this->settings->isRecaptchaConfigured());
    }

    public function testModuleNameCarriesThePluginId(): void
    {
        $this->assertSame("plugin_authgrd", \ilAuthGuardSettings::MODULE);
    }

    public function testProviderRoundTrip(): void
    {
        $this->settings->setProvider(\ilAuthGuardSettings::PROVIDER_RECAPTCHA);

        $this->assertSame(\ilAuthGuardSettings::PROVIDER_RECAPTCHA, $this->settings->getProvider());
        $this->assertSame("recaptcha", $this->rows["provider"]);
    }

    public function testUnknownProviderIsRefused(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->settings->setProvider("hcaptcha");
    }

    public function testUnknownStoredProviderReadsAsAltcha(): void
    {
        $this->rows["provider"] = "something";

        $this->assertSame(\ilAuthGuardSettings::PROVIDER_ALTCHA, $this->settings->getProvider());
    }

    public function testRecaptchaWithoutKeysFallsBackToAltchaInEffect(): void
    {
        $this->settings->setProvider(\ilAuthGuardSettings::PROVIDER_RECAPTCHA);
        $this->assertSame(\ilAuthGuardSettings::PROVIDER_ALTCHA, $this->settings->getEffectiveProvider());

        $this->settings->setRecaptchaSiteKey(self::SITE_KEY);
        $this->assertSame(\ilAuthGuardSettings::PROVIDER_ALTCHA, $this->settings->getEffectiveProvider());

        $this->settings->setRecaptchaSecretKey(self::SECRET_KEY);
        $this->assertSame(\ilAuthGuardSettings::PROVIDER_RECAPTCHA, $this->settings->getEffectiveProvider());
    }

    public function testSecretKeyIsEncryptedAtRest(): void
    {
        $this->settings->setRecaptchaSecretKey(self::SECRET_KEY);

        $stored = $this->rows["recaptcha_secret_key"];
        $this->assertStringStartsWith("v1:", $stored);
        $this->assertStringNotContainsString(self::SECRET_KEY, $stored);
        $this->assertSame(self::SECRET_KEY, $this->settings->getRecaptchaSecretKey());
        $this->assertTrue($this->settings->hasRecaptchaSecretKey());
    }

    public function testTwoEncryptionsOfTheSameSecretDiffer(): void
    {
        $this->settings->setRecaptchaSecretKey(self::SECRET_KEY);
        $first = $this->rows["recaptcha_secret_key"];
        $this->settings->setRecaptchaSecretKey(self::SECRET_KEY);

        $this->assertNotSame($first, $this->rows["recaptcha_secret_key"]);
    }

    public function testEmptySecretKeepsTheStoredOne(): void
    {
        $this->settings->setRecaptchaSecretKey(self::SECRET_KEY);
        $stored = $this->rows["recaptcha_secret_key"];

        $this->settings->setRecaptchaSecretKey("");

        $this->assertSame($stored, $this->rows["recaptcha_secret_key"]);
        $this->assertSame(self::SECRET_KEY, $this->settings->getRecaptchaSecretKey());
    }

    public function testTheKeyIsCreatedOnceAndReused(): void
    {
        $this->settings->setRecaptchaSecretKey(self::SECRET_KEY);
        $key_file = $this->files["authgrd/encryption.sec"];

        $other = new \ilAuthGuardSettings($this->makeStore(), $this->makeStorage());
        $other->setRecaptchaSecretKey("ANOTHERSECRETKEYOFTHEGOOGLESHAPE");

        $this->assertSame($key_file, $this->files["authgrd/encryption.sec"]);
    }

    public function testMissingEncryptionKeyFailsInsteadOfReturningGarbage(): void
    {
        $this->settings->setRecaptchaSecretKey(self::SECRET_KEY);
        $this->files = [];

        $this->expectException(\RuntimeException::class);
        $this->settings->getRecaptchaSecretKey();
    }

    public function testTamperedSecretFailsToDecrypt(): void
    {
        $this->settings->setRecaptchaSecretKey(self::SECRET_KEY);
        $this->rows["recaptcha_secret_key"] = "v1:" . base64_encode(str_repeat("x", 60));

        $this->expectException(\RuntimeException::class);
        $this->settings->getRecaptchaSecretKey();
    }

    public function testValueWithoutPrefixIsReadAsPlaintext(): void
    {
        $this->rows["recaptcha_secret_key"] = self::SECRET_KEY;

        $this->assertSame(self::SECRET_KEY, $this->settings->getRecaptchaSecretKey());
    }

    public function testAskingWhetherASecretIsStoredDoesNotTouchTheFilesystem(): void
    {
        $storage = $this->createMock(\ILIAS\Filesystem\Filesystem::class);
        $storage->expects($this->never())->method("has");
        $storage->expects($this->never())->method("read");
        $settings = new \ilAuthGuardSettings($this->makeStore(), $storage);
        $this->rows["recaptcha_secret_key"] = "v1:abc";
        $this->rows["recaptcha_site_key"] = self::SITE_KEY;

        $this->assertTrue($settings->hasRecaptchaSecretKey());
        $this->assertTrue($settings->isRecaptchaConfigured());
    }

    public function testDeleteAllRemovesTheRows(): void
    {
        $this->settings->setProvider(\ilAuthGuardSettings::PROVIDER_RECAPTCHA);
        $this->settings->setRecaptchaSiteKey(self::SITE_KEY);
        $this->settings->setRecaptchaSecretKey(self::SECRET_KEY);

        $this->settings->deleteAll();

        $this->assertSame([], $this->rows);
        $this->assertSame(\ilAuthGuardSettings::PROVIDER_ALTCHA, $this->settings->getProvider());
    }

    public function testAltchaNeedsNoKeys(): void
    {
        $this->assertSame([], \ilAuthGuardSettings::validate("altcha", "", "", false));
    }

    public function testRecaptchaWithoutKeysIsRefused(): void
    {
        $errors = \ilAuthGuardSettings::validate("recaptcha", "", "", false);

        $this->assertSame(
            ["recaptcha_site_key" => "cfg_err_site_key", "recaptcha_secret_key" => "cfg_err_secret_key"],
            $errors
        );
    }

    public function testRecaptchaWithoutTheSecretKeyIsRefused(): void
    {
        $errors = \ilAuthGuardSettings::validate("recaptcha", self::SITE_KEY, "", false);

        $this->assertSame(["recaptcha_secret_key" => "cfg_err_secret_key"], $errors);
    }

    public function testRecaptchaWithoutTheSiteKeyIsRefusedEvenWithAStoredSecret(): void
    {
        $errors = \ilAuthGuardSettings::validate("recaptcha", "", "", true);

        $this->assertSame(["recaptcha_site_key" => "cfg_err_site_key"], $errors);
    }

    public function testStoredSecretMayBeLeftEmpty(): void
    {
        $this->assertSame([], \ilAuthGuardSettings::validate("recaptcha", self::SITE_KEY, "", true));
    }

    public function testBothKeysGivenIsValid(): void
    {
        $this->assertSame(
            [],
            \ilAuthGuardSettings::validate("recaptcha", self::SITE_KEY, self::SECRET_KEY, false)
        );
    }

    public function testMalformedKeysAreRefused(): void
    {
        $errors = \ilAuthGuardSettings::validate("recaptcha", "short", "has space and \"quotes\"", true);

        $this->assertSame(
            ["recaptcha_site_key" => "cfg_err_site_key", "recaptcha_secret_key" => "cfg_err_secret_key"],
            $errors
        );
    }

    public function testKeyWithATrailingNewlineIsRefused(): void
    {
        $errors = \ilAuthGuardSettings::validate("recaptcha", self::SITE_KEY . "\n", self::SECRET_KEY, false);

        $this->assertArrayHasKey("recaptcha_site_key", $errors);
    }

    public function testUnknownProviderIsRefusedByTheValidation(): void
    {
        $errors = \ilAuthGuardSettings::validate("other", self::SITE_KEY, self::SECRET_KEY, true);

        $this->assertSame(["provider" => "cfg_err_provider"], $errors);
    }
}
