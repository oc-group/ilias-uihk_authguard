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

class RecaptchaTest extends TestCase
{
    use SettingsFixture;

    private const SECRET_KEY = "6LeIxAcTAAAAAGG-vFI1TnRWxMZNFuojJ4WifJWe";

    private const ANSWER = "03AFcWeA-visitor-answer-token";

    private \ilLogger $logger;

    private \ilAuthGuardRecaptcha $recaptcha;

    /** @var object{reply: string, failure: \Throwable|null, calls: array<int, array<mixed>>} */
    private object $transport;

    protected function setUp(): void
    {
        $settings = $this->makeSettings();
        $settings->setProviderSecret("recaptcha", "secret_key", self::SECRET_KEY);

        $this->logger = $this->createMock(\ilLogger::class);
        $this->transport = new class () {
            public string $reply = "{\"success\": true}";

            public ?\Throwable $failure = null;

            /** @var array<int, array<mixed>> */
            public array $calls = [];
        };

        $this->recaptcha = new class ($settings, $this->logger, $this->transport) extends \ilAuthGuardRecaptcha {
            public function __construct(
                \ilAuthGuardSettings $settings,
                \ilLogger $logger,
                private readonly object $transport
            ) {
                parent::__construct($settings, $logger);
            }

            protected function post(string $url, array $fields): string
            {
                $this->transport->calls[] = [$url, $fields];
                if ($this->transport->failure !== null) {
                    throw $this->transport->failure;
                }

                return $this->transport->reply;
            }
        };
    }

    /**
     * Expects exactly one warning naming the reason and carrying neither
     * the secret key nor the visitor's answer.
     */
    private function expectWarning(string $reason): void
    {
        $this->logger->expects($this->once())
            ->method("warning")
            ->with($this->callback(
                static fn (string $message): bool => str_starts_with(
                    $message,
                    "AuthGuard: reCAPTCHA verification failed"
                )
                    && str_contains($message, $reason)
                    && !str_contains($message, self::SECRET_KEY)
                    && !str_contains($message, self::ANSWER)
            ));
    }

    public function testConfirmedAnswerPasses(): void
    {
        $this->logger->expects($this->never())->method("warning");

        $this->assertTrue($this->recaptcha->verify(self::ANSWER));
    }

    public function testTheRequestGoesToGoogleWithSecretAndAnswerOnly(): void
    {
        $this->recaptcha->verify(self::ANSWER);

        $this->assertCount(1, $this->transport->calls);
        [$url, $fields] = $this->transport->calls[0];
        $this->assertSame("https://www.google.com/recaptcha/api/siteverify", $url);
        $this->assertSame(["secret" => self::SECRET_KEY, "response" => self::ANSWER], $fields);
    }

    public function testRejectedAnswerFailsAndNamesGoogleErrorCodes(): void
    {
        $this->transport->reply = "{\"success\": false, \"error-codes\": "
            . "[\"invalid-input-response\", \"timeout-or-duplicate\"]}";
        $this->expectWarning("rejected: invalid-input-response, timeout-or-duplicate");

        $this->assertFalse($this->recaptcha->verify(self::ANSWER));
    }

    public function testRejectedAnswerWithoutCodesStillFails(): void
    {
        $this->transport->reply = "{\"success\": false}";
        $this->expectWarning("rejected");

        $this->assertFalse($this->recaptcha->verify(self::ANSWER));
    }

    public function testOnlyWellFormedErrorCodesReachTheLog(): void
    {
        $this->transport->reply = "{\"success\": false, \"error-codes\": [\"bad-request\", \"EVIL <script>\", 7]}";
        $this->logger->expects($this->once())
            ->method("warning")
            ->with($this->logicalAnd(
                $this->stringContains("bad-request"),
                $this->logicalNot($this->stringContains("script"))
            ));

        $this->assertFalse($this->recaptcha->verify(self::ANSWER));
    }

    public function testSuccessThatIsNotTheBooleanTrueFails(): void
    {
        $this->transport->reply = "{\"success\": \"true\"}";
        $this->expectWarning("rejected");

        $this->assertFalse($this->recaptcha->verify(self::ANSWER));
    }

    public function testUnreachableServiceFailsClosed(): void
    {
        $this->transport->failure = new \RuntimeException("Could not resolve host");
        $this->expectWarning("service_unreachable: Could not resolve host");

        $this->assertFalse($this->recaptcha->verify(self::ANSWER));
    }

    public function testTimeoutFailsClosed(): void
    {
        $this->transport->failure = new \RuntimeException("Operation timed out after 5001 milliseconds");
        $this->expectWarning("service_unreachable");

        $this->assertFalse($this->recaptcha->verify(self::ANSWER));
    }

    public function testUnreadableReplyFailsClosed(): void
    {
        $this->transport->reply = "<html>502</html>";
        $this->expectWarning("reply_unreadable");

        $this->assertFalse($this->recaptcha->verify(self::ANSWER));
    }

    public function testEmptyReplyFailsClosed(): void
    {
        $this->transport->reply = "";
        $this->expectWarning("reply_unreadable");

        $this->assertFalse($this->recaptcha->verify(self::ANSWER));
    }

    public function testEmptyAnswerIsNotSentToGoogle(): void
    {
        $this->expectWarning("response_shape");

        $this->assertFalse($this->recaptcha->verify(""));
        $this->assertSame([], $this->transport->calls);
    }

    public function testOversizedAnswerIsNotSentToGoogle(): void
    {
        $this->expectWarning("response_shape");
        $answer = str_repeat("a", \ilAuthGuardRecaptcha::MAX_RESPONSE_LENGTH + 1);

        $this->assertFalse($this->recaptcha->verify($answer));
        $this->assertSame([], $this->transport->calls);
    }

    public function testMissingSecretFailsWithoutCallingGoogle(): void
    {
        $this->rows = [];
        $this->expectWarning("secret_missing");

        $this->assertFalse($this->recaptcha->verify(self::ANSWER));
        $this->assertSame([], $this->transport->calls);
    }

    public function testUnreadableSecretFailsWithoutCallingGoogle(): void
    {
        $this->files = [];
        $this->expectWarning("secret_unavailable");

        $this->assertFalse($this->recaptcha->verify(self::ANSWER));
        $this->assertSame([], $this->transport->calls);
    }
}
