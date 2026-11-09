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

use GuzzleHttp\Psr7\ServerRequest;
use ILIAS\Data\Factory as DataFactory;
use ILIAS\Refinery\Factory as Refinery;
use ILIAS\UI\Component\Input\Container\Form\Standard;
use ILIAS\UI\Implementation\Component\Input\Container\Form\Factory as FormFactory;
use ILIAS\UI\Implementation\Component\Input\Field\Factory as FieldFactory;
use ILIAS\UI\Implementation\Component\SignalGenerator;
use PHPUnit\Framework\TestCase;

require_once __DIR__ . "/../SettingsFixture.php";

/**
 * The configuration form built from the real UI Framework factories: its
 * structure, how a submit is read and checked, and how it reaches the
 * settings.
 */
class ConfigFormTest extends TestCase
{
    use SettingsFixture;

    private const GOOGLE_SITE_KEY = "6LeIxAcTAAAAAJcZVRqyHh71UMIEGNQ_MXjiZKhI";

    private const GOOGLE_SECRET = "6LeIxAcTAAAAAGG-vFI1TnRWxMZNFuojJ4WifJWe";

    private \ilAuthGuardProviderRegistry $registry;

    private \ilAuthGuardConfigForm $builder;

    protected function setUp(): void
    {
        if (!class_exists(FieldFactory::class)) {
            $this->markTestSkipped("ILIAS UI classes not available.");
        }

        $this->registry = \ilAuthGuardProviderRegistry::createDefault();

        $data = new DataFactory();
        $language = $this->createMock(\ILIAS\Language\Language::class);
        $refinery = new Refinery($data, $language);
        $fields = new FieldFactory(
            $this->createMock(\ILIAS\UI\Implementation\Component\Input\UploadLimitResolver::class),
            new SignalGenerator(),
            $data,
            $refinery,
            $language
        );

        $container = $this->createMock(\ILIAS\UI\Component\Input\Container\Factory::class);
        $container->method("form")->willReturn(new FormFactory($fields, new SignalGenerator()));
        $input = $this->createMock(\ILIAS\UI\Component\Input\Factory::class);
        $input->method("field")->willReturn($fields);
        $input->method("container")->willReturn($container);
        $ui = $this->createMock(\ILIAS\UI\Factory::class);
        $ui->method("input")->willReturn($input);

        $this->builder = new \ilAuthGuardConfigForm(
            $ui,
            $refinery,
            $this->registry,
            static fn (string $key): string => "T[" . $key . "]"
        );
    }

    private function build(?\ilAuthGuardSettings $settings = null, bool $disabled = false): Standard
    {
        $settings ??= $this->makeSettings();

        return $this->builder->build(
            "post-url",
            \ilAuthGuardConfigState::fromSettings($settings, $this->registry),
            $disabled,
            "Save"
        );
    }

    /**
     * @return object the switchable group of a form
     */
    private function choice(object $form): object
    {
        return $form->getInputs()[\ilAuthGuardConfigState::SECTION]
            ->getInputs()[\ilAuthGuardConfigState::KEY_PROVIDER];
    }

    /**
     * The POST body that selects a provider and fills its fields.
     *
     * @param array<string, string> $values field name => text
     * @return array<string, string>
     */
    private function body(Standard $form, string $provider, array $values, bool $accept = false): array
    {
        $section = $form->getInputs()[\ilAuthGuardConfigState::SECTION];
        $choice = $section->getInputs()[\ilAuthGuardConfigState::KEY_PROVIDER];

        $body = [$choice->getName() => $provider];
        foreach ($values as $name => $value) {
            $body[$choice->getInputs()[$provider]->getInputs()[$name]->getName()] = $value;
        }
        if ($accept) {
            $body[$section->getInputs()[\ilAuthGuardConfigState::KEY_ACCEPT]->getName()] = "checked";
        }

        return $body;
    }

    private function submit(Standard $form, array $body): Standard
    {
        return $form->withRequest((new ServerRequest("POST", "http://localhost/"))->withParsedBody($body));
    }

    /**
     * Submits as the screen does and returns what it would store, or null
     * when the form refuses the input.
     *
     * @param array<string, string> $values
     */
    private function save(
        \ilAuthGuardSettings $settings,
        string $provider,
        array $values,
        bool $accept = false
    ): ?\ilAuthGuardConfigState {
        $submitted = $this->submit($this->build($settings), $this->body($this->build($settings), $provider, $values, $accept));
        $data = $submitted->getData();
        if ($data === null) {
            return null;
        }

        $state = \ilAuthGuardConfigState::fromFormData($data, $settings, $this->registry);
        $this->assertNotNull($state);
        $this->assertSame([], $state->validate($this->registry));
        $state->applyTo($settings, $this->registry);

        return $state;
    }

    public function testTheFormIsOneSectionWithTheChoiceAndTheCheckbox(): void
    {
        $form = $this->build();

        $this->assertSame([\ilAuthGuardConfigState::SECTION], array_keys($form->getInputs()));
        $section = $form->getInputs()[\ilAuthGuardConfigState::SECTION];
        $this->assertSame("T[cfg_section_provider]", $section->getLabel());
        $this->assertSame(
            [\ilAuthGuardConfigState::KEY_PROVIDER, \ilAuthGuardConfigState::KEY_ACCEPT],
            array_keys($section->getInputs())
        );
        $this->assertSame("post-url", $form->getPostURL());
        $this->assertSame("Save", $form->getSubmitLabel());
    }

    public function testTheChoiceHasOneGroupPerProviderInDisplayOrder(): void
    {
        $choice = $this->choice($this->build());

        $this->assertSame("T[cfg_provider]", $choice->getLabel());
        $this->assertInstanceOf(\ILIAS\UI\Component\Input\Field\SwitchableGroup::class, $choice);
        $this->assertSame(array_keys($this->registry->all()), array_keys($choice->getInputs()));
    }

    public function testEachGroupCarriesItsProvidersFields(): void
    {
        $choice = $this->choice($this->build());

        foreach ($this->registry->all() as $id => $provider) {
            $expected = array_map(
                static fn (\ilAuthGuardProviderField $field): string => $field->name,
                $provider->getSettingsFields()
            );
            $this->assertSame($expected, array_keys($choice->getInputs()[$id]->getInputs()), $id);
            $this->assertSame("T[cfg_provider_" . $id . "]", $choice->getInputs()[$id]->getLabel());
        }
    }

    public function testOnlyExternalProvidersCarryThePrivacyNoteInTheByline(): void
    {
        $choice = $this->choice($this->build());

        foreach ($this->registry->all() as $id => $provider) {
            $byline = $choice->getInputs()[$id]->getByline();

            $this->assertStringStartsWith("T[cfg_provider_" . $id . "_info]", $byline);
            $this->assertSame($provider->isExternal(), str_contains($byline, "T[cfg_provider_external_note]"), $id);
        }
    }

    public function testFieldTypes(): void
    {
        $recaptcha3 = $this->choice($this->build())->getInputs()["recaptcha3"]->getInputs();
        $friendly = $this->choice($this->build())->getInputs()["friendlycaptcha"]->getInputs();

        $this->assertInstanceOf(\ILIAS\UI\Component\Input\Field\Text::class, $recaptcha3["site_key"]);
        $this->assertInstanceOf(\ILIAS\UI\Component\Input\Field\Password::class, $recaptcha3["secret_key"]);
        $this->assertInstanceOf(\ILIAS\UI\Component\Input\Field\Text::class, $recaptcha3["threshold"]);
        $this->assertInstanceOf(\ILIAS\UI\Component\Input\Field\Password::class, $friendly["api_key"]);
        $this->assertInstanceOf(\ILIAS\UI\Component\Input\Field\Select::class, $friendly["endpoint"]);
        $this->assertInstanceOf(
            \ILIAS\UI\Component\Input\Field\Checkbox::class,
            $this->build()->getInputs()[\ilAuthGuardConfigState::SECTION]
                ->getInputs()[\ilAuthGuardConfigState::KEY_ACCEPT]
        );
    }

    public function testTheCheckboxCarriesTheLabelAndTheByline(): void
    {
        $accept = $this->build()->getInputs()[\ilAuthGuardConfigState::SECTION]
            ->getInputs()[\ilAuthGuardConfigState::KEY_ACCEPT];

        $this->assertSame("T[cfg_accept_unreachable]", $accept->getLabel());
        $this->assertSame("T[cfg_accept_unreachable_info]", $accept->getByline());
    }

    public function testTheFormShowsTheStoredValuesAndNeverASecret(): void
    {
        $settings = $this->makeSettings();
        $settings->setProvider("friendlycaptcha");
        $settings->setProviderValue("friendlycaptcha", "site_key", "FCMGEMUD2KTDSQ5H");
        $settings->setProviderValue("friendlycaptcha", "endpoint", "eu");
        $settings->setProviderSecret("friendlycaptcha", "api_key", "A1B2C3D4E5F6G7H8I9J0K1L2");
        $settings->setAcceptWhenUnreachable(true);

        $form = $this->build($settings);
        $choice = $this->choice($form);
        $inputs = $choice->getInputs()["friendlycaptcha"]->getInputs();

        $this->assertSame("friendlycaptcha", $choice->getValue()[0]);
        $this->assertSame("FCMGEMUD2KTDSQ5H", $inputs["site_key"]->getValue());
        $this->assertSame("eu", $inputs["endpoint"]->getValue());
        $this->assertNull($inputs["api_key"]->getValue());
        $this->assertSame("T[cfg_secret_key_stored]", $inputs["api_key"]->getByline());
        $this->assertTrue(
            $form->getInputs()[\ilAuthGuardConfigState::SECTION]->getInputs()[\ilAuthGuardConfigState::KEY_ACCEPT]
                ->getValue()
        );
        $this->assertStringNotContainsString("A1B2C3D4E5F6G7H8I9J0K1L2", serialize($this->rows) . print_r($form->getInputs(), true));
    }

    public function testASecretThatIsNotStoredSaysSo(): void
    {
        $inputs = $this->choice($this->build())->getInputs()["turnstile"]->getInputs();

        $this->assertSame("T[cfg_secret_key_info]", $inputs["secret_key"]->getByline());
    }

    public function testTheFirstProviderIsAltchaAndNeedsNothing(): void
    {
        $settings = $this->makeSettings();

        $state = $this->save($settings, "altcha", []);

        $this->assertNotNull($state);
        $this->assertSame("altcha", $settings->getProvider());
        $this->assertFalse($settings->isAcceptWhenUnreachable());
    }

    public function testASubmitStoresTheValuesAndEncryptsTheSecret(): void
    {
        $settings = $this->makeSettings();

        $this->save($settings, "recaptcha", ["site_key" => self::GOOGLE_SITE_KEY, "secret_key" => self::GOOGLE_SECRET]);

        $this->assertSame("recaptcha", $this->rows["provider"]);
        $this->assertSame(self::GOOGLE_SITE_KEY, $this->rows["recaptcha_site_key"]);
        $this->assertStringStartsWith("v1:", $this->rows["recaptcha_secret_key"]);
        $this->assertSame(self::GOOGLE_SECRET, $settings->getProviderSecret("recaptcha", "secret_key"));
    }

    public function testAnEmptySecretKeepsTheStoredOne(): void
    {
        $settings = $this->makeSettings();
        $settings->setProviderSecret("recaptcha", "secret_key", self::GOOGLE_SECRET);
        $settings->setProviderValue("recaptcha", "site_key", self::GOOGLE_SITE_KEY);
        $stored = $this->rows["recaptcha_secret_key"];

        $state = $this->save($settings, "recaptcha", ["site_key" => self::GOOGLE_SITE_KEY, "secret_key" => ""]);

        $this->assertNotNull($state);
        $this->assertSame($stored, $this->rows["recaptcha_secret_key"]);
        $this->assertSame(self::GOOGLE_SECRET, $settings->getProviderSecret("recaptcha", "secret_key"));
    }

    public function testAnEmptySecretWithNoneStoredIsRefusedOnTheSecretField(): void
    {
        $form = $this->build();
        $submitted = $this->submit($form, $this->body($form, "recaptcha", [
            "site_key" => self::GOOGLE_SITE_KEY,
            "secret_key" => "",
        ]));
        $inputs = $this->choice($submitted)->getInputs()["recaptcha"]->getInputs();

        $this->assertNull($submitted->getData());
        $this->assertSame("T[cfg_err_secret_key]", $inputs["secret_key"]->getError());
        $this->assertNull($inputs["site_key"]->getError());
    }

    public function testAMalformedSiteKeyIsRefusedOnTheSiteKeyField(): void
    {
        $form = $this->build();
        $submitted = $this->submit($form, $this->body($form, "turnstile", [
            "site_key" => "short",
            "secret_key" => "0x4AAAAAAAyyyyyyyyyyyyyyyyyyyyyyyyyyy",
        ]));
        $inputs = $this->choice($submitted)->getInputs()["turnstile"]->getInputs();

        $this->assertNull($submitted->getData());
        $this->assertSame("T[cfg_err_turnstile_site_key]", $inputs["site_key"]->getError());
        $this->assertNull($inputs["secret_key"]->getError());
    }

    public function testTheOtherProvidersFieldsAreNotChecked(): void
    {
        $settings = $this->makeSettings();

        $state = $this->save($settings, "hcaptcha", [
            "site_key" => "10000000-ffff-ffff-ffff-000000000001",
            "secret_key" => "test-hcaptcha-secret-not-real",
        ]);

        $this->assertNotNull($state);
        $this->assertSame("hcaptcha", $settings->getProvider());
        $this->assertArrayNotHasKey("recaptcha_site_key", $this->rows);
    }

    public function testTheThresholdIsCheckedOnItsOwnField(): void
    {
        $form = $this->build();
        $base = ["site_key" => self::GOOGLE_SITE_KEY, "secret_key" => self::GOOGLE_SECRET];

        $bad = $this->submit($form, $this->body($form, "recaptcha3", $base + ["threshold" => "1.5"]));
        $inputs = $this->choice($bad)->getInputs()["recaptcha3"]->getInputs();
        $this->assertNull($bad->getData());
        $this->assertSame("T[cfg_err_threshold]", $inputs["threshold"]->getError());

        $settings = $this->makeSettings();
        $this->save($settings, "recaptcha3", $base + ["threshold" => "0.7"]);
        $this->assertSame(0.7, \ilAuthGuardProviderRecaptcha3::readThreshold($settings));
    }

    public function testFriendlyCaptchaStoresItsEndpoint(): void
    {
        $settings = $this->makeSettings();

        $this->save($settings, "friendlycaptcha", [
            "site_key" => "FCMGEMUD2KTDSQ5H",
            "api_key" => "A1B2C3D4E5F6G7H8I9J0K1L2",
            "endpoint" => "eu",
        ]);

        $this->assertSame("eu", $this->rows["friendlycaptcha_endpoint"]);
        $this->assertSame("A1B2C3D4E5F6G7H8I9J0K1L2", $settings->getProviderSecret("friendlycaptcha", "api_key"));
    }

    public function testNoProviderInputIsMarkedRequired(): void
    {
        // A required input inside a group makes the whole provider option carry the asterisk.
        foreach ($this->choice($this->build())->getInputs() as $id => $group) {
            $this->assertFalse($group->isRequired(), $id);
            foreach ($group->getInputs() as $name => $input) {
                $this->assertFalse($input->isRequired(), $id . "/" . $name);
            }
        }
    }

    public function testFriendlyCaptchaRefusesAnEmptyEndpointOnItsOwnField(): void
    {
        $form = $this->build();
        $submitted = $this->submit($form, $this->body($form, "friendlycaptcha", [
            "site_key" => "FCMGEMUD2KTDSQ5H",
            "api_key" => "A1B2C3D4E5F6G7H8I9J0K1L2",
            "endpoint" => "",
        ]));
        $inputs = $this->choice($submitted)->getInputs()["friendlycaptcha"]->getInputs();

        $this->assertNull($submitted->getData());
        $this->assertSame("T[cfg_err_endpoint]", $inputs["endpoint"]->getError());
    }

    public function testTheCheckboxRoundTrips(): void
    {
        $settings = $this->makeSettings();

        $this->save($settings, "altcha", [], true);
        $this->assertTrue($settings->isAcceptWhenUnreachable());
        $this->assertTrue(
            $this->build($settings)->getInputs()[\ilAuthGuardConfigState::SECTION]
                ->getInputs()[\ilAuthGuardConfigState::KEY_ACCEPT]->getValue()
        );

        $this->save($settings, "altcha", [], false);
        $this->assertFalse($settings->isAcceptWhenUnreachable());
    }

    public function testTheFormCanBeShownReadOnly(): void
    {
        $this->assertFalse($this->build()->getInputs()[\ilAuthGuardConfigState::SECTION]->isDisabled());
        $this->assertTrue($this->build(null, true)->getInputs()[\ilAuthGuardConfigState::SECTION]->isDisabled());
    }

    public function testTheStateReadsTheStoredSettings(): void
    {
        $settings = $this->makeSettings();
        $settings->setProvider("hcaptcha");
        $settings->setProviderSecret("hcaptcha", "secret_key", "test-hcaptcha-secret-not-real");

        $state = \ilAuthGuardConfigState::fromSettings($settings, $this->registry);

        $this->assertSame("hcaptcha", $state->provider);
        $this->assertTrue($state->secrets_stored["hcaptcha"]["secret_key"]);
        $this->assertFalse($state->secrets_stored["turnstile"]["secret_key"]);
        $this->assertSame("global", $state->values["friendlycaptcha"]["endpoint"]);
        $this->assertSame("0.5", $state->values["recaptcha3"]["threshold"]);
        $this->assertArrayNotHasKey("secret_key", $state->values["hcaptcha"]);
        $this->assertFalse($state->accept);
    }

    public function testMalformedFormDataIsNotAState(): void
    {
        $settings = $this->makeSettings();

        $this->assertNull(\ilAuthGuardConfigState::fromFormData(null, $settings, $this->registry));
        $this->assertNull(\ilAuthGuardConfigState::fromFormData([], $settings, $this->registry));
        $this->assertNull(\ilAuthGuardConfigState::fromFormData(
            [\ilAuthGuardConfigState::SECTION => [\ilAuthGuardConfigState::KEY_PROVIDER => ["nope", []]]],
            $settings,
            $this->registry
        ));
    }

    public function testTheStateValidatesWithTheProviderAndNamesTheInputs(): void
    {
        $state = new \ilAuthGuardConfigState("recaptcha", ["recaptcha" => ["site_key" => "", "secret_key" => ""]], [
            "recaptcha" => ["secret_key" => false],
        ], false);

        $this->assertSame(
            ["recaptcha_site_key" => "cfg_err_site_key", "recaptcha_secret_key" => "cfg_err_secret_key"],
            $state->validate($this->registry)
        );
    }

    public function testOverlayKeepsTheOtherProvidersAndTakesTheSubmittedOnes(): void
    {
        $settings = $this->makeSettings();
        $settings->setProviderValue("hcaptcha", "site_key", "10000000-ffff-ffff-ffff-000000000001");
        $stored = \ilAuthGuardConfigState::fromSettings($settings, $this->registry);
        $submitted = new \ilAuthGuardConfigState("turnstile", ["turnstile" => ["site_key" => "TYPED"]], [], true);

        $merged = $stored->overlay($submitted);

        $this->assertSame("turnstile", $merged->provider);
        $this->assertSame("TYPED", $merged->values["turnstile"]["site_key"]);
        $this->assertSame("10000000-ffff-ffff-ffff-000000000001", $merged->values["hcaptcha"]["site_key"]);
        $this->assertTrue($merged->accept);
    }
}
