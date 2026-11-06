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
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ServerRequestInterface;

require_once __DIR__ . "/ArraySessionStore.php";
require_once __DIR__ . "/SettingsFixture.php";

/**
 * The form protection with each selectable external provider: what is
 * rendered, in which order the checks run, what a failure looks like and
 * what the visitor without JavaScript gets. The vendor call is a mock.
 */
class ProviderFormProtectionTest extends TestCase
{
    use SettingsFixture;

    private const DWELL = 10.0;

    private const GENERIC = "t:security_check_failed";

    private ArraySessionStore $store;

    private \ilLogger $logger;

    private \ilAuthGuardSettings $settings;

    /** @var object{clock: float, markup_vars: array<string, string>} */
    private object $probe;

    /**
     * @return array<string, array{0: string, 1: class-string, 2: string, 3: string, 4: string}>
     */
    public static function providers(): array
    {
        return [
            "recaptcha3" => [
                "recaptcha3", \ilAuthGuardRecaptcha3::class, "authguard_recaptcha3", "recaptcha3", "RECAPTCHA3_SITE_KEY",
            ],
            "turnstile" => [
                "turnstile", \ilAuthGuardTurnstile::class, "cf-turnstile-response", "turnstile", "TURNSTILE_SITE_KEY",
            ],
            "hcaptcha" => [
                "hcaptcha", \ilAuthGuardHcaptcha::class, "h-captcha-response", "hcaptcha", "HCAPTCHA_SITE_KEY",
            ],
            "friendlycaptcha" => [
                "friendlycaptcha", \ilAuthGuardFriendlyCaptcha::class, "frc-captcha-response", "friendlycaptcha",
                "FRIENDLYCAPTCHA_SITE_KEY",
            ],
        ];
    }

    protected function setUp(): void
    {
        $this->store = new ArraySessionStore();
        $this->logger = $this->createMock(\ilLogger::class);
        $this->settings = $this->makeSettings();
        $this->probe = new class () {
            public float $clock = 1000.0;

            /** @var array<string, string> */
            public array $markup_vars = [];
        };
    }

    private function select(string $id, bool $complete = true): void
    {
        $this->settings->setProvider($id);
        if (!$complete) {
            return;
        }

        $this->settings->setProviderValue($id, "site_key", "SITE-KEY-" . $id);
        $field = $id === "friendlycaptcha" ? "api_key" : "secret_key";
        $this->settings->setProviderSecret($id, $field, "plain-secret-value-123456");
    }

    private function facade(object $verifier, string $id): \ilAuthGuardFormProtection
    {
        $registry = \ilAuthGuardProviderRegistry::createDefault([$id => $verifier]);
        $probe = $this->probe;

        return new class ($this->store, $this->logger, $this->settings, $registry, $probe) extends \ilAuthGuardFormProtection {
            public function __construct(
                \ilAuthGuardSessionStore $store,
                \ilLogger $logger,
                \ilAuthGuardSettings $settings,
                \ilAuthGuardProviderRegistry $registry,
                private readonly object $probe
            ) {
                parent::__construct($store, null, $logger, $settings, null, $registry);
            }

            protected function now(): float
            {
                return $this->probe->clock;
            }

            protected function translate(string $lang_key): string
            {
                return "t:" . $lang_key;
            }

            protected function getEndpointUrl(string $command, string $form_id): string
            {
                return "url/" . $command . "/" . $form_id;
            }

            protected function getAssetUrl(string $path): string
            {
                return "asset" . $path;
            }

            protected function registerAssets(): void
            {
            }

            protected function renderMarkup(array $variables): string
            {
                $this->probe->markup_vars = $variables;

                return "<markup/>";
            }
        };
    }

    /**
     * @param array<string, mixed> $body
     */
    private function request(array $body): ServerRequestInterface
    {
        return (new ServerRequest("POST", "http://localhost/"))->withParsedBody($body);
    }

    private function state(string $form_id): \ilAuthGuardFormState
    {
        return new \ilAuthGuardFormState($this->store, $form_id);
    }

    private function renderAndWait(\ilAuthGuardFormProtection $facade, string $form_id = "f"): string
    {
        $facade->render($form_id);
        $this->probe->clock += self::DWELL;

        return (string) $this->state($form_id)->get(\ilAuthGuardFormState::FIELD_HONEYPOT);
    }

    #[DataProvider("providers")]
    public function testRenderCarriesOnlyTheSelectedProvidersValues(
        string $id,
        string $verifier_class,
        string $field,
        string $reason,
        string $site_var
    ): void {
        $this->select($id);

        $this->facade($this->createMock($verifier_class), $id)->render("contact");
        $vars = $this->probe->markup_vars;

        $this->assertSame($id, $vars["PROVIDER"]);
        $this->assertSame("SITE-KEY-" . $id, $vars[$site_var]);
        $this->assertSame("contact", $vars["FORM_ID"]);
        $this->assertSame("", $vars["CHALLENGE_URL"]);
        $this->assertSame("", $vars["RECAPTCHA_SITE_KEY"]);
        $this->assertNull($this->state("contact")->get(\ilAuthGuardFormState::FIELD_POW_SECRET));
        $this->assertNotNull($this->state("contact")->get(\ilAuthGuardFormState::FIELD_RENDERED_AT));
    }

    #[DataProvider("providers")]
    public function testConfirmedAnswerPasses(
        string $id,
        string $verifier_class,
        string $field,
        string $reason,
        string $site_var
    ): void {
        $this->select($id);
        $verifier = $this->createMock($verifier_class);
        $verifier->expects($this->once())->method("verify")->with("the-answer", "f")->willReturn(true);
        $facade = $this->facade($verifier, $id);
        $name = $this->renderAndWait($facade);

        $result = $facade->verify("f", $this->request([$field => "the-answer", $name => ""]));

        $this->assertTrue($result->isPassed());
        $this->assertSame("", $result->getMessage());
    }

    #[DataProvider("providers")]
    public function testRefusedAnswerFailsWithTheProvidersReasonAndTheUnifiedMessage(
        string $id,
        string $verifier_class,
        string $field,
        string $reason,
        string $site_var
    ): void {
        $this->select($id);
        $verifier = $this->createMock($verifier_class);
        $verifier->method("verify")->willReturn(false);
        $facade = $this->facade($verifier, $id);
        $this->renderAndWait($facade);
        $this->state("f")->set(\ilAuthGuardFormState::FIELD_PHRASE, "abc12");

        $result = $facade->verify("f", $this->request([
            $field => "the-answer",
            \ilAuthGuardFormProtection::FIELD_CAPTCHA => "abc12",
        ]));

        $this->assertFalse($result->isPassed());
        $this->assertSame($reason, $result->getReason());
        $this->assertSame(self::GENERIC, $result->getMessage());
    }

    #[DataProvider("providers")]
    public function testVisitorWithoutJavaScriptGetsTheImageCaptcha(
        string $id,
        string $verifier_class,
        string $field,
        string $reason,
        string $site_var
    ): void {
        $this->select($id);
        $verifier = $this->createMock($verifier_class);
        $verifier->expects($this->never())->method("verify");
        $facade = $this->facade($verifier, $id);
        $this->renderAndWait($facade);
        $this->state("f")->set(\ilAuthGuardFormState::FIELD_PHRASE, "abc12");

        $result = $facade->verify("f", $this->request([
            $field => "",
            \ilAuthGuardFormProtection::FIELD_CAPTCHA => "abc12",
        ]));

        $this->assertTrue($result->isPassed());
    }

    #[DataProvider("providers")]
    public function testEmptySubmitIsRejectedWithoutAskingTheVendor(
        string $id,
        string $verifier_class,
        string $field,
        string $reason,
        string $site_var
    ): void {
        $this->select($id);
        $verifier = $this->createMock($verifier_class);
        $verifier->expects($this->never())->method("verify");
        $facade = $this->facade($verifier, $id);
        $this->renderAndWait($facade);

        $result = $facade->verify("f", $this->request([]));

        $this->assertSame(\ilAuthGuardVerificationResult::REASON_CAPTCHA, $result->getReason());
    }

    #[DataProvider("providers")]
    public function testVendorIsNotAskedBeforeTimingAndHoneypotPass(
        string $id,
        string $verifier_class,
        string $field,
        string $reason,
        string $site_var
    ): void {
        $this->select($id);
        $verifier = $this->createMock($verifier_class);
        $verifier->expects($this->never())->method("verify");
        $facade = $this->facade($verifier, $id);

        $facade->render("fast");
        $this->probe->clock += 1.0;
        $fast = $facade->verify("fast", $this->request([$field => "the-answer"]));

        $name = $this->renderAndWait($facade, "trap");
        $trap = $facade->verify("trap", $this->request([$field => "the-answer", $name => "x"]));

        $this->assertSame(\ilAuthGuardVerificationResult::REASON_TIMING, $fast->getReason());
        $this->assertSame(\ilAuthGuardVerificationResult::REASON_HONEYPOT, $trap->getReason());
    }

    #[DataProvider("providers")]
    public function testAnswerOfAnotherProviderIsIgnored(
        string $id,
        string $verifier_class,
        string $field,
        string $reason,
        string $site_var
    ): void {
        $this->select($id);
        $verifier = $this->createMock($verifier_class);
        $verifier->expects($this->never())->method("verify");
        $facade = $this->facade($verifier, $id);
        $this->renderAndWait($facade);

        $result = $facade->verify("f", $this->request([
            \ilAuthGuardFormProtection::FIELD_POW => "garbage",
            \ilAuthGuardFormProtection::FIELD_RECAPTCHA => "the-answer",
        ]));

        $this->assertSame(\ilAuthGuardVerificationResult::REASON_CAPTCHA, $result->getReason());
    }

    #[DataProvider("providers")]
    public function testFailedCheckIsLoggedAsARejectedSubmit(
        string $id,
        string $verifier_class,
        string $field,
        string $reason,
        string $site_var
    ): void {
        $this->select($id);
        $verifier = $this->createMock($verifier_class);
        $verifier->method("verify")->willReturn(false);
        $facade = $this->facade($verifier, $id);
        $this->renderAndWait($facade, "contact");
        $this->logger->expects($this->once())
            ->method("warning")
            ->with($this->callback(
                static fn (string $message): bool => str_contains($message, "contact")
                    && str_contains($message, "reason: " . $reason)
            ));

        $facade->verify("contact", $this->request([$field => "the-answer"]));
    }

    #[DataProvider("providers")]
    public function testIncompleteSettingsUseAltchaAndSaySo(
        string $id,
        string $verifier_class,
        string $field,
        string $reason,
        string $site_var
    ): void {
        $this->select($id, false);
        $verifier = $this->createMock($verifier_class);
        $verifier->expects($this->never())->method("verify");
        $this->logger->expects($this->atLeastOnce())
            ->method("error")
            ->with($this->logicalAnd($this->stringContains("keys are incomplete"), $this->stringContains($id)));

        $this->facade($verifier, $id)->render("f");

        $this->assertSame("altcha", $this->probe->markup_vars["PROVIDER"]);
        $this->assertNotNull($this->state("f")->get(\ilAuthGuardFormState::FIELD_POW_SECRET));
    }

    public function testSeveralFormsKeepTheirOwnState(): void
    {
        $this->select("turnstile");
        $verifier = $this->createMock(\ilAuthGuardTurnstile::class);
        $verifier->expects($this->exactly(2))->method("verify")->willReturnCallback(
            static fn (string $answer, string $form_id): bool => $answer === "answer-for-" . $form_id
        );
        $facade = $this->facade($verifier, "turnstile");
        $first = $this->renderAndWait($facade, "one");
        $second = $this->renderAndWait($facade, "two");

        $wrong = $facade->verify("one", $this->request(["cf-turnstile-response" => "answer-for-two", $first => ""]));
        $right = $facade->verify("two", $this->request(["cf-turnstile-response" => "answer-for-two", $second => ""]));

        $this->assertFalse($wrong->isPassed());
        $this->assertTrue($right->isPassed());
    }

    public function testRecaptcha3ActionFollowsTheForm(): void
    {
        $this->select("recaptcha3");
        $facade = $this->facade($this->createMock(\ilAuthGuardRecaptcha3::class), "recaptcha3");

        $facade->render("registration");
        $this->assertSame("authguard_registration", $this->probe->markup_vars["RECAPTCHA3_ACTION"]);
        $facade->render("contact-us");
        $this->assertSame("authguard_contact_us", $this->probe->markup_vars["RECAPTCHA3_ACTION"]);
    }

    public function testFriendlyCaptchaEndpointIsRendered(): void
    {
        $this->select("friendlycaptcha");
        $this->settings->setProviderValue("friendlycaptcha", "endpoint", "eu");
        $facade = $this->facade($this->createMock(\ilAuthGuardFriendlyCaptcha::class), "friendlycaptcha");

        $facade->render("f");

        $this->assertSame("eu", $this->probe->markup_vars["FRIENDLYCAPTCHA_ENDPOINT"]);
        $this->assertSame("asset/js/authguard-friendlycaptcha.js", $this->probe->markup_vars["FRIENDLYCAPTCHA_SCRIPT_URL"]);
    }

    /**
     * A verifier mock that fails the way the given outage or refusal does.
     */
    private function failing(string $class, bool $unreachable): object
    {
        $verifier = $this->createMock($class);
        $verifier->method("verify")->willReturn(false);
        $verifier->method("wasUnreachable")->willReturn($unreachable);

        return $verifier;
    }

    #[DataProvider("providers")]
    public function testUnreachableVendorRejectsByDefault(
        string $id,
        string $verifier_class,
        string $field,
        string $reason,
        string $site_var
    ): void {
        $this->select($id);
        $this->assertFalse($this->settings->isAcceptWhenUnreachable());
        $facade = $this->facade($this->failing($verifier_class, true), $id);
        $name = $this->renderAndWait($facade);

        $result = $facade->verify("f", $this->request([$field => "the-answer", $name => ""]));

        $this->assertFalse($result->isPassed());
        $this->assertSame($reason, $result->getReason());
        $this->assertSame(self::GENERIC, $result->getMessage());
    }

    #[DataProvider("providers")]
    public function testUnreachableVendorIsAcceptedWhenTheOptionIsOnAndTheSkipIsLogged(
        string $id,
        string $verifier_class,
        string $field,
        string $reason,
        string $site_var
    ): void {
        $this->select($id);
        $this->settings->setAcceptWhenUnreachable(true);
        $facade = $this->facade($this->failing($verifier_class, true), $id);
        $name = $this->renderAndWait($facade, "contact");
        $this->logger->expects($this->once())
            ->method("warning")
            ->with($this->callback(
                static fn (string $message): bool => str_starts_with($message, "AuthGuard: submit accepted")
                    && str_contains($message, "form: contact")
                    && str_contains($message, "provider: " . $id)
                    && str_contains($message, "unreachable")
            ));

        $result = $facade->verify("contact", $this->request([$field => "the-answer", $name => ""]));

        $this->assertTrue($result->isPassed());
        $this->assertSame("", $result->getMessage());
    }

    #[DataProvider("providers")]
    public function testRefusedAnswerIsStillRejectedWhenTheOptionIsOn(
        string $id,
        string $verifier_class,
        string $field,
        string $reason,
        string $site_var
    ): void {
        $this->select($id);
        $this->settings->setAcceptWhenUnreachable(true);
        $facade = $this->facade($this->failing($verifier_class, false), $id);
        $name = $this->renderAndWait($facade);

        $result = $facade->verify("f", $this->request([$field => "the-answer", $name => ""]));

        $this->assertFalse($result->isPassed());
        $this->assertSame($reason, $result->getReason());
    }

    #[DataProvider("providers")]
    public function testTimingAndHoneypotStillRejectWhenTheOptionIsOn(
        string $id,
        string $verifier_class,
        string $field,
        string $reason,
        string $site_var
    ): void {
        $this->select($id);
        $this->settings->setAcceptWhenUnreachable(true);
        $verifier = $this->createMock($verifier_class);
        $verifier->expects($this->never())->method("verify");
        $facade = $this->facade($verifier, $id);

        $facade->render("fast");
        $this->probe->clock += 1.0;
        $fast = $facade->verify("fast", $this->request([$field => "a"]));
        $name = $this->renderAndWait($facade, "trap");
        $trap = $facade->verify("trap", $this->request([$field => "a", $name => "x"]));

        $this->assertSame(\ilAuthGuardVerificationResult::REASON_TIMING, $fast->getReason());
        $this->assertSame(\ilAuthGuardVerificationResult::REASON_HONEYPOT, $trap->getReason());
    }

    #[DataProvider("providers")]
    public function testAnEmptyProviderFieldKeepsTheImageFallbackWhenTheOptionIsOn(
        string $id,
        string $verifier_class,
        string $field,
        string $reason,
        string $site_var
    ): void {
        $this->select($id);
        $this->settings->setAcceptWhenUnreachable(true);
        $verifier = $this->createMock($verifier_class);
        $verifier->expects($this->never())->method("verify");
        $facade = $this->facade($verifier, $id);
        $this->renderAndWait($facade);

        $result = $facade->verify("f", $this->request([$field => ""]));

        $this->assertSame(\ilAuthGuardVerificationResult::REASON_CAPTCHA, $result->getReason());
    }

    public function testTheOptionDoesNotTouchAltcha(): void
    {
        $this->settings->setAcceptWhenUnreachable(true);
        $facade = $this->facade($this->createMock(\ilAuthGuardTurnstile::class), "turnstile");
        $name = $this->renderAndWait($facade);

        $result = $facade->verify("f", $this->request([
            \ilAuthGuardFormProtection::FIELD_POW => "garbage",
            $name => "",
        ]));

        $this->assertSame(\ilAuthGuardVerificationResult::REASON_POW, $result->getReason());
    }
}
