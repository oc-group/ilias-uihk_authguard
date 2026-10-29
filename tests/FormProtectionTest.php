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

use AltchaOrg\Altcha\Algorithm\Pbkdf2;
use AltchaOrg\Altcha\Altcha;
use AltchaOrg\Altcha\Challenge;
use AltchaOrg\Altcha\Payload;
use AltchaOrg\Altcha\SolveChallengeOptions;
use GuzzleHttp\Psr7\ServerRequest;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ServerRequestInterface;

require_once __DIR__ . "/ArraySessionStore.php";

class FormProtectionTest extends TestCase
{
    private const DWELL = 10.0;

    private ArraySessionStore $store;

    private \ilAuthGuardProofOfWork $pow;

    private \ilLogger $logger;

    /** @var object{clock: float, markup_vars: array<string, string>} */
    private object $facade_probe;

    private \ilAuthGuardFormProtection $facade;

    protected function setUp(): void
    {
        $this->store = new ArraySessionStore();
        $this->pow = new \ilAuthGuardProofOfWork(10, 1, 5);
        $this->logger = $this->createMock(\ilLogger::class);

        $this->facade_probe = new class () {
            public float $clock = 1000.0;

            /** @var array<string, string> */
            public array $markup_vars = [];
        };
        $probe = $this->facade_probe;

        $this->facade = new class (
            $this->store,
            $this->pow,
            $this->logger,
            $probe
        ) extends \ilAuthGuardFormProtection {
            public function __construct(
                \ilAuthGuardSessionStore $store,
                \ilAuthGuardProofOfWork $pow,
                \ilLogger $logger,
                private readonly object $probe
            ) {
                parent::__construct($store, $pow, $logger);
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
     * @return ServerRequestInterface
     */
    private function request(array $body): ServerRequestInterface
    {
        return (new ServerRequest("POST", "http://localhost/"))->withParsedBody($body);
    }

    private function state(string $form_id): \ilAuthGuardFormState
    {
        return new \ilAuthGuardFormState($this->store, $form_id);
    }

    /**
     * Renders the form, lets the dwell time pass and returns the honeypot name.
     */
    private function renderAndWait(string $form_id = "f"): string
    {
        $this->facade->render($form_id);
        $this->facade_probe->clock += self::DWELL;

        return (string) $this->state($form_id)->get(\ilAuthGuardFormState::FIELD_HONEYPOT);
    }

    /**
     * @return array<string, mixed> a body with a solved proof-of-work payload
     */
    private function solvedPowBody(string $form_id = "f"): array
    {
        $state = $this->state($form_id);
        $challenge = Challenge::fromArray($this->pow->issueChallenge($state));
        $solution = (new Altcha())->solveChallenge(new SolveChallengeOptions(
            algorithm: new Pbkdf2(),
            challenge: $challenge,
            timeout: 10.0
        ));
        $this->assertNotNull($solution);

        return [\ilAuthGuardFormProtection::FIELD_POW => (new Payload($challenge, $solution))->toBase64()];
    }

    public function testApiVersionIsOne(): void
    {
        $this->assertSame(1, \ilAuthGuardFormProtection::API_VERSION);
    }

    public function testRenderRecordsTheStateUnderTheFormId(): void
    {
        $this->assertSame("<markup/>", $this->facade->render("contact"));

        $state = $this->state("contact");
        $this->assertSame(1000.0, $state->get(\ilAuthGuardFormState::FIELD_RENDERED_AT));
        $this->assertNotSame("", (string) $state->get(\ilAuthGuardFormState::FIELD_HONEYPOT));
        $this->assertNotSame("", (string) $state->get(\ilAuthGuardFormState::FIELD_POW_SECRET));
        foreach (array_keys($this->store->data) as $key) {
            $this->assertStringStartsWith("authguard.contact.", $key);
        }
    }

    public function testRenderHandsTheFragmentItsVariables(): void
    {
        $this->facade->render("contact");
        $vars = $this->facade_probe->markup_vars;
        $honeypot = (string) $this->state("contact")->get(\ilAuthGuardFormState::FIELD_HONEYPOT);

        $this->assertSame("contact", $vars["FORM_ID"]);
        $this->assertSame($honeypot, $vars["HONEYPOT_NAME"]);
        $this->assertSame("authguard_pow", $vars["POW_FIELD"]);
        $this->assertSame("captcha_code", $vars["CAPTCHA_FIELD"]);
        $this->assertSame("url/challenge/contact", $vars["CHALLENGE_URL"]);
        $this->assertSame("url/showImage/contact", $vars["IMAGE_URL"]);
        $this->assertSame("asset/js/authguard-widget.js", $vars["WIDGET_SCRIPT_URL"]);
    }

    public function testRenderRejectsAMalformedFormId(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->facade->render("Bad Id");
    }

    public function testVerifyRejectsAMalformedFormId(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->facade->verify("../x", $this->request([]));
    }

    public function testTwoRendersUseDifferentHoneypotNamesPerFormId(): void
    {
        $this->facade->render("form-a");
        $this->facade->render("form-b");

        $this->assertNotSame(
            $this->state("form-a")->get(\ilAuthGuardFormState::FIELD_HONEYPOT),
            $this->state("form-b")->get(\ilAuthGuardFormState::FIELD_HONEYPOT)
        );
    }

    public function testUnrenderedFormFailsWithMissingState(): void
    {
        $result = $this->facade->verify("f", $this->request([]));

        $this->assertFalse($result->isPassed());
        $this->assertSame(\ilAuthGuardVerificationResult::REASON_MISSING_STATE, $result->getReason());
        $this->assertSame("t:form_state_missing", $result->getMessage());
    }

    public function testTooFastSubmitFailsWithTiming(): void
    {
        $this->facade->render("f");
        $this->facade_probe->clock += 1.9;

        $result = $this->facade->verify("f", $this->request($this->solvedPowBody()));

        $this->assertSame(\ilAuthGuardVerificationResult::REASON_TIMING, $result->getReason());
        $this->assertSame("t:submit_too_fast", $result->getMessage());
    }

    public function testSubmitAtTheThresholdIsNotTooFast(): void
    {
        $this->facade->render("f");
        $this->facade_probe->clock += \ilAuthGuardFormProtection::MIN_SUBMIT_INTERVAL_SECONDS;

        $result = $this->facade->verify("f", $this->request($this->solvedPowBody()));

        $this->assertTrue($result->isPassed());
    }

    public function testTimingIsCheckedBeforeTheHoneypot(): void
    {
        $this->facade->render("f");
        $name = (string) $this->state("f")->get(\ilAuthGuardFormState::FIELD_HONEYPOT);

        $result = $this->facade->verify("f", $this->request([$name => "bot"]));

        $this->assertSame(\ilAuthGuardVerificationResult::REASON_TIMING, $result->getReason());
    }

    public function testFilledHoneypotFails(): void
    {
        $name = $this->renderAndWait();
        $body = $this->solvedPowBody() + [$name => "x"];

        $result = $this->facade->verify("f", $this->request($body));

        $this->assertSame(\ilAuthGuardVerificationResult::REASON_HONEYPOT, $result->getReason());
        $this->assertSame("t:security_check_failed", $result->getMessage());
    }

    public function testHoneypotIsCheckedBeforeProofOfWork(): void
    {
        $name = $this->renderAndWait();

        $result = $this->facade->verify("f", $this->request([
            $name => "x",
            \ilAuthGuardFormProtection::FIELD_POW => "garbage",
        ]));

        $this->assertSame(\ilAuthGuardVerificationResult::REASON_HONEYPOT, $result->getReason());
    }

    public function testEmptyHoneypotWithSolvedProofOfWorkPasses(): void
    {
        $name = $this->renderAndWait();
        $body = $this->solvedPowBody() + [$name => ""];

        $result = $this->facade->verify("f", $this->request($body));

        $this->assertTrue($result->isPassed());
        $this->assertSame("", $result->getMessage());
    }

    public function testInvalidProofOfWorkFails(): void
    {
        $this->renderAndWait();

        $result = $this->facade->verify("f", $this->request([
            \ilAuthGuardFormProtection::FIELD_POW => "garbage",
        ]));

        $this->assertSame(\ilAuthGuardVerificationResult::REASON_POW, $result->getReason());
        $this->assertSame("t:pow_failed", $result->getMessage());
    }

    public function testInvalidProofOfWorkDoesNotFallBackToTheCaptcha(): void
    {
        $this->renderAndWait();
        $this->state("f")->set(\ilAuthGuardFormState::FIELD_PHRASE, "abc12");

        $result = $this->facade->verify("f", $this->request([
            \ilAuthGuardFormProtection::FIELD_POW => "garbage",
            \ilAuthGuardFormProtection::FIELD_CAPTCHA => "abc12",
        ]));

        $this->assertSame(\ilAuthGuardVerificationResult::REASON_POW, $result->getReason());
    }

    public function testReplayedProofOfWorkFailsOnTheNextRender(): void
    {
        $this->renderAndWait();
        $body = $this->solvedPowBody();
        $this->assertTrue($this->facade->verify("f", $this->request($body))->isPassed());

        $this->renderAndWait();
        $result = $this->facade->verify("f", $this->request($body));

        $this->assertSame(\ilAuthGuardVerificationResult::REASON_POW, $result->getReason());
    }

    public function testMissingProofOfWorkRequiresTheCaptcha(): void
    {
        $this->renderAndWait();
        $this->state("f")->set(\ilAuthGuardFormState::FIELD_PHRASE, "abc12");

        $result = $this->facade->verify("f", $this->request([]));

        $this->assertSame(\ilAuthGuardVerificationResult::REASON_CAPTCHA, $result->getReason());
        $this->assertSame("t:captcha_required", $result->getMessage());
    }

    public function testMissingProofOfWorkWithoutAnImageSaysTheCheckWasNotFinished(): void
    {
        $this->renderAndWait();

        $result = $this->facade->verify("f", $this->request([]));

        $this->assertSame(\ilAuthGuardVerificationResult::REASON_CAPTCHA, $result->getReason());
        $this->assertSame("t:pow_missing", $result->getMessage());
    }

    public function testCorrectCaptchaPassesWithoutProofOfWork(): void
    {
        $this->renderAndWait();
        $this->state("f")->set(\ilAuthGuardFormState::FIELD_PHRASE, "AbC12");

        $result = $this->facade->verify("f", $this->request([
            \ilAuthGuardFormProtection::FIELD_CAPTCHA => " abc12 ",
        ]));

        $this->assertTrue($result->isPassed());
    }

    public function testWrongCaptchaFails(): void
    {
        $this->renderAndWait();
        $this->state("f")->set(\ilAuthGuardFormState::FIELD_PHRASE, "abc12");

        $result = $this->facade->verify("f", $this->request([
            \ilAuthGuardFormProtection::FIELD_CAPTCHA => "zzz",
        ]));

        $this->assertSame(\ilAuthGuardVerificationResult::REASON_CAPTCHA, $result->getReason());
        $this->assertSame("t:captcha_validation_failed", $result->getMessage());
    }

    public function testCaptchaWithoutAnIssuedPhraseFails(): void
    {
        $this->renderAndWait();

        $result = $this->facade->verify("f", $this->request([
            \ilAuthGuardFormProtection::FIELD_CAPTCHA => "abc12",
        ]));

        $this->assertSame("t:pow_missing", $result->getMessage());
    }

    public function testArrayValuedFieldsFailClosed(): void
    {
        $this->renderAndWait();
        $this->state("f")->set(\ilAuthGuardFormState::FIELD_PHRASE, "abc12");

        $result = $this->facade->verify("f", $this->request([
            \ilAuthGuardFormProtection::FIELD_CAPTCHA => ["abc12"],
        ]));

        $this->assertFalse($result->isPassed());
    }

    public function testCaptchaIsSingleUse(): void
    {
        $this->renderAndWait();
        $this->state("f")->set(\ilAuthGuardFormState::FIELD_PHRASE, "abc12");
        $request = $this->request([\ilAuthGuardFormProtection::FIELD_CAPTCHA => "abc12"]);

        $this->assertTrue($this->facade->verify("f", $request)->isPassed());
        $second = $this->facade->verify("f", $request);

        $this->assertSame(\ilAuthGuardVerificationResult::REASON_MISSING_STATE, $second->getReason());
    }

    public function testStateIsConsumedWhateverTheOutcome(): void
    {
        $this->renderAndWait();

        $this->facade->verify("f", $this->request([]));

        $this->assertSame([], $this->store->data);
    }

    public function testMissingParsedBodyFailsInsteadOfRaising(): void
    {
        $this->renderAndWait();

        $result = $this->facade->verify("f", new ServerRequest("POST", "http://localhost/"));

        $this->assertFalse($result->isPassed());
    }

    public function testTwoFormIdsDoNotInterfere(): void
    {
        $this->renderAndWait("form-a");
        $this->renderAndWait("form-b");
        $this->state("form-a")->set(\ilAuthGuardFormState::FIELD_PHRASE, "aaaa1");
        $this->state("form-b")->set(\ilAuthGuardFormState::FIELD_PHRASE, "bbbb2");

        $a = $this->facade->verify("form-a", $this->request([
            \ilAuthGuardFormProtection::FIELD_CAPTCHA => "aaaa1",
        ]));
        $b = $this->facade->verify("form-b", $this->request([
            \ilAuthGuardFormProtection::FIELD_CAPTCHA => "bbbb2",
        ]));

        $this->assertTrue($a->isPassed());
        $this->assertTrue($b->isPassed());
    }

    public function testAnswerOfOneFormDoesNotPassAnother(): void
    {
        $this->renderAndWait("form-a");
        $this->renderAndWait("form-b");
        $this->state("form-a")->set(\ilAuthGuardFormState::FIELD_PHRASE, "aaaa1");
        $this->state("form-b")->set(\ilAuthGuardFormState::FIELD_PHRASE, "bbbb2");

        $result = $this->facade->verify("form-b", $this->request([
            \ilAuthGuardFormProtection::FIELD_CAPTCHA => "aaaa1",
        ]));

        $this->assertSame(\ilAuthGuardVerificationResult::REASON_CAPTCHA, $result->getReason());
        $this->assertSame("aaaa1", $this->state("form-a")->get(\ilAuthGuardFormState::FIELD_PHRASE));
        $this->assertNull($this->state("form-b")->get(\ilAuthGuardFormState::FIELD_PHRASE));
    }

    public function testVerifyingOneFormLeavesTheOtherVerifiable(): void
    {
        $this->renderAndWait("form-a");
        $this->renderAndWait("form-b");
        $this->facade->verify("form-a", $this->request([]));

        $body = $this->solvedPowBody("form-b");
        $result = $this->facade->verify("form-b", $this->request($body));

        $this->assertTrue($result->isPassed());
    }

    public function testRejectionIsLoggedWithFormIdAndReason(): void
    {
        $this->renderAndWait("contact");
        $this->logger->expects($this->once())
            ->method("warning")
            ->with($this->callback(
                static fn (string $message): bool => str_contains($message, "contact")
                    && str_contains($message, "captcha")
                    && str_starts_with($message, "AuthGuard:")
            ));

        $this->facade->verify("contact", $this->request([]));
    }

    public function testPassIsNotLogged(): void
    {
        $this->renderAndWait();
        $this->logger->expects($this->never())->method("warning");

        $this->facade->verify("f", $this->request($this->solvedPowBody()));
    }
}
