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

require_once __DIR__ . "/SettingsFixture.php";
require_once __DIR__ . "/FakeSiteverify.php";

/**
 * The server-side check of every external provider, with the HTTP call
 * replaced: success, vendor refusal, unreachable vendor, malformed reply,
 * and what each vendor needs besides.
 */
class SiteverifyTest extends TestCase
{
    use SettingsFixture;

    private const SECRET = "SECRET-key-0123456789-abcdef";

    private const SITE_KEY = "SITE-key-0123456789-abcdef";

    private const ANSWER = "visitor-answer-token";

    private \ilLogger $logger;

    /**
     * @return array<string, array{0: class-string<\ilAuthGuardSiteverify>, 1: string, 2: string}>
     */
    public static function vendors(): array
    {
        return [
            "recaptcha" => [FakeRecaptcha::class, "recaptcha", "secret_key"],
            "recaptcha3" => [FakeRecaptcha3::class, "recaptcha3", "secret_key"],
            "turnstile" => [FakeTurnstile::class, "turnstile", "secret_key"],
            "hcaptcha" => [FakeHcaptcha::class, "hcaptcha", "secret_key"],
            "friendlycaptcha" => [FakeFriendlyCaptcha::class, "friendlycaptcha", "api_key"],
        ];
    }

    protected function setUp(): void
    {
        $this->logger = $this->createMock(\ilLogger::class);
    }

    /**
     * @param class-string<\ilAuthGuardSiteverify> $class
     * @param array<string, string> $values plaintext settings of the provider by field name
     * @return \ilAuthGuardSiteverify&object
     */
    private function make(string $class, string $provider, string $secret_field, array $values = []): object
    {
        $settings = $this->makeSettings();
        $settings->setProviderValue($provider, "site_key", self::SITE_KEY);
        $settings->setProviderSecret($provider, $secret_field, self::SECRET);
        foreach ($values as $field => $value) {
            $settings->setProviderValue($provider, $field, $value);
        }

        return new $class($settings, $this->logger);
    }

    /**
     * Expects exactly one warning naming the reason and carrying neither
     * the secret nor the visitor's answer.
     */
    private function expectWarning(string $label, string $reason): void
    {
        $this->logger->expects($this->once())
            ->method("warning")
            ->with($this->callback(
                static fn (string $message): bool => str_starts_with(
                    $message,
                    "AuthGuard: " . $label . " verification failed"
                )
                    && str_contains($message, $reason)
                    && !str_contains($message, self::SECRET)
                    && !str_contains($message, self::ANSWER)
            ));
    }

    #[DataProvider("vendors")]
    public function testConfirmedAnswerPassesWithoutALogLine(string $class, string $provider, string $field): void
    {
        $verifier = $this->make($class, $provider, $field);
        $verifier->reply = $this->successReply($class);
        $this->logger->expects($this->never())->method("warning");

        $this->assertTrue($verifier->verify(self::ANSWER, "contact"));
        $this->assertCount(1, $verifier->calls);
    }

    #[DataProvider("vendors")]
    public function testUnreachableVendorFailsClosed(string $class, string $provider, string $field): void
    {
        $verifier = $this->make($class, $provider, $field);
        $verifier->failure = new \RuntimeException("Could not resolve host");
        $this->logger->expects($this->once())
            ->method("warning")
            ->with($this->stringContains("service_unreachable: Could not resolve host"));

        $this->assertFalse($verifier->verify(self::ANSWER, "contact"));
    }

    #[DataProvider("vendors")]
    public function testNon200StatusFailsClosed(string $class, string $provider, string $field): void
    {
        $verifier = $this->make($class, $provider, $field);
        $verifier->failure = new \RuntimeException("HTTP status 503");
        $this->logger->expects($this->once())
            ->method("warning")
            ->with($this->stringContains("service_unreachable: HTTP status 503"));

        $this->assertFalse($verifier->verify(self::ANSWER, "contact"));
    }

    #[DataProvider("vendors")]
    public function testMalformedReplyFailsClosed(string $class, string $provider, string $field): void
    {
        $verifier = $this->make($class, $provider, $field);
        $verifier->reply = "<html>502 Bad Gateway</html>";
        $this->logger->expects($this->once())
            ->method("warning")
            ->with($this->stringContains("reply_unreadable"));

        $this->assertFalse($verifier->verify(self::ANSWER, "contact"));
    }

    #[DataProvider("vendors")]
    public function testEmptyReplyFailsClosed(string $class, string $provider, string $field): void
    {
        $verifier = $this->make($class, $provider, $field);
        $verifier->reply = "";
        $this->logger->expects($this->once())
            ->method("warning")
            ->with($this->stringContains("reply_unreadable"));

        $this->assertFalse($verifier->verify(self::ANSWER, "contact"));
    }

    #[DataProvider("vendors")]
    public function testReplyThatIsNotAnObjectFailsClosed(string $class, string $provider, string $field): void
    {
        $verifier = $this->make($class, $provider, $field);
        $verifier->reply = "true";

        $this->assertFalse($verifier->verify(self::ANSWER, "contact"));
    }

    #[DataProvider("vendors")]
    public function testSuccessThatIsNotTheBooleanTrueFails(string $class, string $provider, string $field): void
    {
        $verifier = $this->make($class, $provider, $field);
        $verifier->reply = "{\"success\": \"true\"}";

        $this->assertFalse($verifier->verify(self::ANSWER, "contact"));
    }

    #[DataProvider("vendors")]
    public function testVendorRefusalFails(string $class, string $provider, string $field): void
    {
        $verifier = $this->make($class, $provider, $field);
        $verifier->reply = "{\"success\": false, \"error-codes\": [\"timeout-or-duplicate\"], "
            . "\"error\": {\"error_code\": \"response_duplicate\"}}";
        $this->logger->expects($this->once())
            ->method("warning")
            ->with($this->stringContains("rejected: "));

        $this->assertFalse($verifier->verify(self::ANSWER, "contact"));
    }

    #[DataProvider("vendors")]
    public function testEmptyAnswerIsNotSentToTheVendor(string $class, string $provider, string $field): void
    {
        $verifier = $this->make($class, $provider, $field);
        $this->logger->expects($this->once())->method("warning")->with($this->stringContains("response_shape"));

        $this->assertFalse($verifier->verify("", "contact"));
        $this->assertSame([], $verifier->calls);
    }

    #[DataProvider("vendors")]
    public function testOversizedAnswerIsNotSentToTheVendor(string $class, string $provider, string $field): void
    {
        $verifier = $this->make($class, $provider, $field);
        $this->logger->expects($this->once())->method("warning")->with($this->stringContains("response_shape"));

        $this->assertFalse($verifier->verify(str_repeat("a", $class::MAX_RESPONSE_LENGTH + 1), "contact"));
        $this->assertSame([], $verifier->calls);
    }

    #[DataProvider("vendors")]
    public function testMissingSecretFailsWithoutCallingTheVendor(string $class, string $provider, string $field): void
    {
        $verifier = new $class($this->makeSettings(), $this->logger);
        $this->logger->expects($this->once())->method("warning")->with($this->stringContains("secret_missing"));

        $this->assertFalse($verifier->verify(self::ANSWER, "contact"));
        $this->assertSame([], $verifier->calls);
    }

    #[DataProvider("vendors")]
    public function testUnreadableSecretFailsWithoutCallingTheVendor(
        string $class,
        string $provider,
        string $field
    ): void {
        $verifier = $this->make($class, $provider, $field);
        $this->files = [];
        $this->logger->expects($this->once())->method("warning")->with($this->stringContains("secret_unavailable"));

        $this->assertFalse($verifier->verify(self::ANSWER, "contact"));
        $this->assertSame([], $verifier->calls);
    }

    #[DataProvider("vendors")]
    public function testErrorCodesOfTheWrongShapeNeverReachTheLog(
        string $class,
        string $provider,
        string $field
    ): void {
        $verifier = $this->make($class, $provider, $field);
        $verifier->reply = "{\"success\": false, \"error-codes\": [\"bad-request\", \"EVIL <script>\", 7]}";
        $this->logger->expects($this->once())
            ->method("warning")
            ->with($this->logicalNot($this->stringContains("script")));

        $this->assertFalse($verifier->verify(self::ANSWER, "contact"));
    }

    /**
     * @param class-string $class
     */
    private function successReply(string $class): string
    {
        if ($class === FakeRecaptcha3::class) {
            return "{\"success\": true, \"score\": 0.9, \"action\": \"authguard_contact\"}";
        }

        return "{\"success\": true}";
    }

    public function testRecaptchaSendsSecretAndAnswerToGoogle(): void
    {
        $verifier = $this->make(FakeRecaptcha::class, "recaptcha", "secret_key");

        $verifier->verify(self::ANSWER, "contact");

        $this->assertSame("https://www.google.com/recaptcha/api/siteverify", $verifier->calls[0]["url"]);
        $this->assertSame(["secret" => self::SECRET, "response" => self::ANSWER], $verifier->calls[0]["fields"]);
        $this->assertSame([], $verifier->calls[0]["headers"]);
    }

    public function testRecaptchaReportsGoogleErrorCodes(): void
    {
        $verifier = $this->make(FakeRecaptcha::class, "recaptcha", "secret_key");
        $verifier->reply = "{\"success\": false, \"error-codes\": [\"invalid-input-response\", \"bad-request\"]}";
        $this->expectWarning("reCAPTCHA", "rejected: invalid-input-response, bad-request");

        $this->assertFalse($verifier->verify(self::ANSWER, "contact"));
    }

    public function testTurnstileSendsSecretAndTokenToCloudflare(): void
    {
        $verifier = $this->make(FakeTurnstile::class, "turnstile", "secret_key");

        $verifier->verify(self::ANSWER, "contact");

        $this->assertSame(
            "https://challenges.cloudflare.com/turnstile/v0/siteverify",
            $verifier->calls[0]["url"]
        );
        $this->assertSame(["secret" => self::SECRET, "response" => self::ANSWER], $verifier->calls[0]["fields"]);
    }

    public function testTurnstileRefusesATokenOverItsDocumentedLength(): void
    {
        $verifier = $this->make(FakeTurnstile::class, "turnstile", "secret_key");

        $this->assertTrue($verifier->verify(str_repeat("a", 2048), "contact"));
        $this->assertFalse($verifier->verify(str_repeat("a", 2049), "contact"));
    }

    public function testTurnstileReportsCloudflareErrorCodes(): void
    {
        $verifier = $this->make(FakeTurnstile::class, "turnstile", "secret_key");
        $verifier->reply = "{\"success\": false, \"error-codes\": [\"timeout-or-duplicate\"]}";
        $this->expectWarning("Turnstile", "rejected: timeout-or-duplicate");

        $this->assertFalse($verifier->verify(self::ANSWER, "contact"));
    }

    public function testHcaptchaSendsSecretTokenAndSiteKey(): void
    {
        $verifier = $this->make(FakeHcaptcha::class, "hcaptcha", "secret_key");

        $verifier->verify(self::ANSWER, "contact");

        $this->assertSame("https://api.hcaptcha.com/siteverify", $verifier->calls[0]["url"]);
        $this->assertSame(
            ["secret" => self::SECRET, "response" => self::ANSWER, "sitekey" => self::SITE_KEY],
            $verifier->calls[0]["fields"]
        );
    }

    public function testHcaptchaReportsItsErrorCodes(): void
    {
        $verifier = $this->make(FakeHcaptcha::class, "hcaptcha", "secret_key");
        $verifier->reply = "{\"success\": false, \"error-codes\": [\"invalid-or-already-seen-response\"]}";
        $this->expectWarning("hCaptcha", "rejected: invalid-or-already-seen-response");

        $this->assertFalse($verifier->verify(self::ANSWER, "contact"));
    }

    public function testFriendlyCaptchaUsesTheGlobalEndpointByDefault(): void
    {
        $verifier = $this->make(FakeFriendlyCaptcha::class, "friendlycaptcha", "api_key");

        $verifier->verify(self::ANSWER, "contact");

        $this->assertSame("https://global.frcapi.com/api/v2/captcha/siteverify", $verifier->calls[0]["url"]);
    }

    public function testFriendlyCaptchaUsesTheEuEndpointWhenChosen(): void
    {
        $verifier = $this->make(FakeFriendlyCaptcha::class, "friendlycaptcha", "api_key", ["endpoint" => "eu"]);

        $verifier->verify(self::ANSWER, "contact");

        $this->assertSame("https://eu.frcapi.com/api/v2/captcha/siteverify", $verifier->calls[0]["url"]);
    }

    public function testFriendlyCaptchaFallsBackToGlobalForAnUnknownEndpoint(): void
    {
        $verifier = $this->make(FakeFriendlyCaptcha::class, "friendlycaptcha", "api_key", ["endpoint" => "mars"]);

        $verifier->verify(self::ANSWER, "contact");

        $this->assertSame("https://global.frcapi.com/api/v2/captcha/siteverify", $verifier->calls[0]["url"]);
    }

    public function testFriendlyCaptchaSendsTheApiKeyInTheHeaderAndTheResponseInTheBody(): void
    {
        $verifier = $this->make(FakeFriendlyCaptcha::class, "friendlycaptcha", "api_key");

        $verifier->verify(self::ANSWER, "contact");

        $this->assertSame(["X-API-Key: " . self::SECRET], $verifier->calls[0]["headers"]);
        $this->assertSame(["response" => self::ANSWER, "sitekey" => self::SITE_KEY], $verifier->calls[0]["fields"]);
        $this->assertStringNotContainsString(self::SECRET, implode("", $verifier->calls[0]["fields"]));
    }

    public function testFriendlyCaptchaReportsItsErrorCode(): void
    {
        $verifier = $this->make(FakeFriendlyCaptcha::class, "friendlycaptcha", "api_key");
        $verifier->reply = "{\"success\": false, \"error\": {\"error_code\": \"response_timeout\", "
            . "\"detail\": \"expired\"}}";
        $this->expectWarning("Friendly Captcha", "rejected: response_timeout");

        $this->assertFalse($verifier->verify(self::ANSWER, "contact"));
    }

    public function testFriendlyCaptchaRefusalWithoutAnErrorObjectStillFails(): void
    {
        $verifier = $this->make(FakeFriendlyCaptcha::class, "friendlycaptcha", "api_key");
        $verifier->reply = "{\"success\": false}";

        $this->assertFalse($verifier->verify(self::ANSWER, "contact"));
    }

    public function testFriendlyCaptchaSuccessThatIsNotABooleanFails(): void
    {
        $verifier = $this->make(FakeFriendlyCaptcha::class, "friendlycaptcha", "api_key");
        $verifier->reply = "{\"success\": 1}";

        $this->assertFalse($verifier->verify(self::ANSWER, "contact"));
    }

    public function testFriendlyCaptchaApiKeyDoesNotStayInTheObjectAfterTheCall(): void
    {
        $verifier = $this->make(FakeFriendlyCaptcha::class, "friendlycaptcha", "api_key");

        $verifier->verify(self::ANSWER, "contact");

        $this->assertStringNotContainsString(self::SECRET, serialize($verifier->calls[0]["fields"]));
        $property = new \ReflectionProperty(\ilAuthGuardSiteverify::class, "secret");
        $this->assertSame("", $property->getValue($verifier));
    }

    private function recaptcha3(string $reply, array $values = []): FakeRecaptcha3
    {
        $verifier = $this->make(FakeRecaptcha3::class, "recaptcha3", "secret_key", $values);
        $verifier->reply = $reply;

        return $verifier;
    }

    public function testRecaptcha3PassesAboveTheDefaultThreshold(): void
    {
        $verifier = $this->recaptcha3("{\"success\": true, \"score\": 0.7, \"action\": \"authguard_registration\"}");

        $this->assertTrue($verifier->verify(self::ANSWER, "registration"));
    }

    public function testRecaptcha3PassesExactlyAtTheThreshold(): void
    {
        $verifier = $this->recaptcha3("{\"success\": true, \"score\": 0.5, \"action\": \"authguard_registration\"}");

        $this->assertTrue($verifier->verify(self::ANSWER, "registration"));
    }

    public function testRecaptcha3RejectsBelowTheDefaultThreshold(): void
    {
        $verifier = $this->recaptcha3("{\"success\": true, \"score\": 0.3, \"action\": \"authguard_registration\"}");
        $this->expectWarning("reCAPTCHA v3", "score_below_threshold (0.30 < 0.50)");

        $this->assertFalse($verifier->verify(self::ANSWER, "registration"));
    }

    public function testRecaptcha3UsesTheConfiguredThreshold(): void
    {
        $reply = "{\"success\": true, \"score\": 0.6, \"action\": \"authguard_registration\"}";

        $this->assertFalse($this->recaptcha3($reply, ["threshold" => "0.7"])->verify(self::ANSWER, "registration"));
        $this->assertTrue($this->recaptcha3($reply, ["threshold" => "0.3"])->verify(self::ANSWER, "registration"));
    }

    public function testRecaptcha3FallsBackToTheDefaultForAnUnreadableThreshold(): void
    {
        $reply = "{\"success\": true, \"score\": 0.4, \"action\": \"authguard_registration\"}";

        $this->assertFalse($this->recaptcha3($reply, ["threshold" => "high"])->verify(self::ANSWER, "registration"));
    }

    public function testRecaptcha3RejectsAWrongAction(): void
    {
        $verifier = $this->recaptcha3("{\"success\": true, \"score\": 0.9, \"action\": \"other_form\"}");
        $this->expectWarning("reCAPTCHA v3", "action_mismatch");

        $this->assertFalse($verifier->verify(self::ANSWER, "registration"));
    }

    public function testRecaptcha3RejectsAMissingAction(): void
    {
        $verifier = $this->recaptcha3("{\"success\": true, \"score\": 0.9}");

        $this->assertFalse($verifier->verify(self::ANSWER, "registration"));
    }

    public function testRecaptcha3RejectsATokenForAnotherFormOfTheSamePage(): void
    {
        $verifier = $this->recaptcha3("{\"success\": true, \"score\": 0.9, \"action\": \"authguard_login\"}");

        $this->assertFalse($verifier->verify(self::ANSWER, "registration"));
    }

    public function testRecaptcha3RejectsAMissingOrMalformedScore(): void
    {
        $head = "{\"success\": true, \"action\": \"authguard_registration\"";

        $this->assertFalse($this->recaptcha3($head . "}")->verify(self::ANSWER, "registration"));
        $this->assertFalse($this->recaptcha3($head . ", \"score\": \"0.9\"}")->verify(self::ANSWER, "registration"));
        $this->assertFalse($this->recaptcha3($head . ", \"score\": 7}")->verify(self::ANSWER, "registration"));
        $this->assertFalse($this->recaptcha3($head . ", \"score\": null}")->verify(self::ANSWER, "registration"));
    }

    public function testRecaptcha3RejectsAFailedCallWhateverTheScore(): void
    {
        $verifier = $this->recaptcha3(
            "{\"success\": false, \"score\": 0.9, \"action\": \"authguard_registration\", "
            . "\"error-codes\": [\"timeout-or-duplicate\"]}"
        );
        $this->expectWarning("reCAPTCHA v3", "rejected: timeout-or-duplicate");

        $this->assertFalse($verifier->verify(self::ANSWER, "registration"));
    }

    public function testRecaptcha3ActionNamesAreMadeOfAllowedCharacters(): void
    {
        $this->assertSame("authguard_registration", \ilAuthGuardRecaptcha3::actionFor("registration"));
        $this->assertSame("authguard_my_form_2", \ilAuthGuardRecaptcha3::actionFor("my-form-2"));
        $this->assertMatchesRegularExpression(
            "/^[A-Za-z0-9_\\/]+$/D",
            \ilAuthGuardRecaptcha3::actionFor("a-b_c-9")
        );
    }

    public function testRecaptcha3SendsTheSameRequestAsV2(): void
    {
        $verifier = $this->recaptcha3("{\"success\": true, \"score\": 0.9, \"action\": \"authguard_registration\"}");

        $verifier->verify(self::ANSWER, "registration");

        $this->assertSame("https://www.google.com/recaptcha/api/siteverify", $verifier->calls[0]["url"]);
        $this->assertSame(["secret" => self::SECRET, "response" => self::ANSWER], $verifier->calls[0]["fields"]);
    }

    #[DataProvider("vendors")]
    public function testATransportFailureCountsAsUnreachable(string $class, string $provider, string $field): void
    {
        $verifier = $this->make($class, $provider, $field);
        $verifier->failure = new \RuntimeException("Operation timed out after 5001 milliseconds");

        $this->assertFalse($verifier->verify(self::ANSWER, "contact"));
        $this->assertTrue($verifier->wasUnreachable());
    }

    #[DataProvider("vendors")]
    public function testAServerErrorCountsAsUnreachable(string $class, string $provider, string $field): void
    {
        $verifier = $this->make($class, $provider, $field);
        $verifier->failure = new \RuntimeException("HTTP status 503");

        $this->assertFalse($verifier->verify(self::ANSWER, "contact"));
        $this->assertTrue($verifier->wasUnreachable());
    }

    #[DataProvider("vendors")]
    public function testAnUnreadableReplyCountsAsUnreachable(string $class, string $provider, string $field): void
    {
        foreach (["<html>502</html>", "", "true"] as $reply) {
            $verifier = $this->make($class, $provider, $field);
            $verifier->reply = $reply;

            $this->assertFalse($verifier->verify(self::ANSWER, "contact"));
            $this->assertTrue($verifier->wasUnreachable(), json_encode($reply));
        }
    }

    #[DataProvider("vendors")]
    public function testAClientErrorStatusIsARejectionNotAnOutage(string $class, string $provider, string $field): void
    {
        $verifier = $this->make($class, $provider, $field);
        $verifier->failure = new \UnexpectedValueException("HTTP status 401");
        $this->logger->expects($this->once())
            ->method("warning")
            ->with($this->stringContains("unexpected_status: HTTP status 401"));

        $this->assertFalse($verifier->verify(self::ANSWER, "contact"));
        $this->assertFalse($verifier->wasUnreachable());
    }

    #[DataProvider("vendors")]
    public function testAWellFormedRefusalIsNeverUnreachable(string $class, string $provider, string $field): void
    {
        $verifier = $this->make($class, $provider, $field);
        $verifier->reply = "{\"success\": false, \"error-codes\": [\"timeout-or-duplicate\"], "
            . "\"error\": {\"error_code\": \"response_timeout\"}}";

        $this->assertFalse($verifier->verify(self::ANSWER, "contact"));
        $this->assertFalse($verifier->wasUnreachable());
    }

    #[DataProvider("vendors")]
    public function testLocalRejectionsAreNeverUnreachable(string $class, string $provider, string $field): void
    {
        $verifier = $this->make($class, $provider, $field);
        $this->assertFalse($verifier->verify("", "contact"));
        $this->assertFalse($verifier->wasUnreachable());
        $this->rows = [];
        $no_secret = new $class($this->makeSettings(), $this->logger);
        $this->assertFalse($no_secret->verify(self::ANSWER, "contact"));
        $this->assertFalse($no_secret->wasUnreachable());
    }

    #[DataProvider("vendors")]
    public function testTheFlagIsResetByTheNextCall(string $class, string $provider, string $field): void
    {
        $verifier = $this->make($class, $provider, $field);
        $verifier->failure = new \RuntimeException("down");
        $verifier->verify(self::ANSWER, "contact");
        $this->assertTrue($verifier->wasUnreachable());

        $verifier->failure = null;
        $verifier->reply = $this->successReply($class);

        $this->assertTrue($verifier->verify(self::ANSWER, "contact"));
        $this->assertFalse($verifier->wasUnreachable());
    }

    public function testRecaptcha3BelowTheThresholdIsNotUnreachable(): void
    {
        $verifier = $this->recaptcha3("{\"success\": true, \"score\": 0.1, \"action\": \"authguard_registration\"}");

        $this->assertFalse($verifier->verify(self::ANSWER, "registration"));
        $this->assertFalse($verifier->wasUnreachable());
    }

    public function testRecaptcha3WrongActionIsNotUnreachable(): void
    {
        $verifier = $this->recaptcha3("{\"success\": true, \"score\": 0.9, \"action\": \"x\"}");

        $this->assertFalse($verifier->verify(self::ANSWER, "registration"));
        $this->assertFalse($verifier->wasUnreachable());
    }
}
