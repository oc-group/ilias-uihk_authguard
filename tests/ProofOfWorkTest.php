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
use AltchaOrg\Altcha\CreateChallengeOptions;
use AltchaOrg\Altcha\Payload;
use AltchaOrg\Altcha\SolveChallengeOptions;
use PHPUnit\Framework\TestCase;

require_once __DIR__ . "/ArraySessionStore.php";

class ProofOfWorkTest extends TestCase
{
    private \ilAuthGuardProofOfWork $pow;

    protected function setUp(): void
    {
        $this->pow = new \ilAuthGuardProofOfWork(10, 1, 5);
    }

    private function makeState(string $form_id = "f"): \ilAuthGuardFormState
    {
        $state = new \ilAuthGuardFormState(new ArraySessionStore(), $form_id);
        $this->pow->resetSecret($state);

        return $state;
    }

    /**
     * Plays the browser: solves a challenge the way the widget does.
     *
     * @param array<string, mixed> $challenge
     * @return Payload
     */
    private function solve(array $challenge): Payload
    {
        $challenge = Challenge::fromArray($challenge);
        $solution = (new Altcha())->solveChallenge(new SolveChallengeOptions(
            algorithm: new Pbkdf2(),
            challenge: $challenge,
            timeout: 10.0
        ));
        $this->assertNotNull($solution);

        return new Payload($challenge, $solution);
    }

    public function testIssuedChallengeHasTheWidgetFormat(): void
    {
        $challenge = $this->pow->issueChallenge($this->makeState());

        $this->assertArrayHasKey("parameters", $challenge);
        $this->assertArrayHasKey("signature", $challenge);
        $this->assertSame("PBKDF2/SHA-256", $challenge["parameters"]["algorithm"]);
        $this->assertSame(10, $challenge["parameters"]["cost"]);
        $this->assertGreaterThan(time(), $challenge["parameters"]["expiresAt"]);
    }

    public function testSolvedChallengeVerifies(): void
    {
        $state = $this->makeState();
        $payload = $this->solve($this->pow->issueChallenge($state));

        $this->assertTrue($this->pow->verify($state, $payload->toBase64()));
    }

    public function testReplayOfASolvedPayloadFails(): void
    {
        $state = $this->makeState();
        $encoded = $this->solve($this->pow->issueChallenge($state))->toBase64();

        $this->assertTrue($this->pow->verify($state, $encoded));
        $this->assertFalse($this->pow->verify($state, $encoded));
    }

    public function testReplayAfterANewChallengeFails(): void
    {
        $state = $this->makeState();
        $encoded = $this->solve($this->pow->issueChallenge($state))->toBase64();
        $this->pow->issueChallenge($state);

        $this->assertFalse($this->pow->verify($state, $encoded));
    }

    public function testFailedAttemptConsumesTheOpenChallenge(): void
    {
        $state = $this->makeState();
        $encoded = $this->solve($this->pow->issueChallenge($state))->toBase64();

        $this->assertFalse($this->pow->verify($state, "garbage"));
        $this->assertFalse($this->pow->verify($state, $encoded));
    }

    public function testTamperedDerivedKeyFails(): void
    {
        $state = $this->makeState();
        $data = $this->solve($this->pow->issueChallenge($state))->toArray();
        $data["solution"]["derivedKey"] = str_repeat("0", strlen($data["solution"]["derivedKey"]));

        $this->assertFalse($this->pow->verify($state, Payload::fromArray($data)->toBase64()));
    }

    public function testTamperedChallengeParametersFail(): void
    {
        $state = $this->makeState();
        $data = $this->solve($this->pow->issueChallenge($state))->toArray();
        $data["challenge"]["parameters"]["cost"] = 1;

        $this->assertFalse($this->pow->verify($state, Payload::fromArray($data)->toBase64()));
    }

    public function testChallengeSignedWithAnotherSecretFails(): void
    {
        $state = $this->makeState("form-a");
        $other = $this->makeState("form-b");
        $foreign = $this->solve($this->pow->issueChallenge($other))->toBase64();
        $this->pow->issueChallenge($state);

        $this->assertFalse($this->pow->verify($state, $foreign));
    }

    public function testSolvedChallengeOfAnEarlierIssueFails(): void
    {
        $state = $this->makeState();
        $first = $this->solve($this->pow->issueChallenge($state))->toBase64();
        $this->pow->issueChallenge($state);

        $this->assertFalse($this->pow->verify($state, $first));
    }

    public function testExpiredChallengeFails(): void
    {
        $state = $this->makeState();
        $secret = (string) $state->get(\ilAuthGuardFormState::FIELD_POW_SECRET);
        $client = new Altcha(
            hmacSignatureSecret: hash_hmac("sha256", "signature", $secret),
            hmacKeySignatureSecret: hash_hmac("sha256", "key", $secret)
        );
        $challenge = $client->createChallenge(new CreateChallengeOptions(
            algorithm: new Pbkdf2(),
            cost: 10,
            counter: 3,
            expiresAt: time() - 5
        ));
        $state->set(\ilAuthGuardFormState::FIELD_POW_CHALLENGE, (string) $challenge->signature);
        $payload = $this->solve($challenge->toArray());

        $this->assertFalse($this->pow->verify($state, $payload->toBase64()));
    }

    public function testVerifyWithoutAnOpenChallengeFails(): void
    {
        $state = $this->makeState();
        $encoded = $this->solve($this->pow->issueChallenge($state))->toBase64();
        $state->clear(\ilAuthGuardFormState::FIELD_POW_CHALLENGE);

        $this->assertFalse($this->pow->verify($state, $encoded));
    }

    public function testMalformedAndOversizedPayloadsFail(): void
    {
        $state = $this->makeState();
        $this->pow->issueChallenge($state);
        $this->assertFalse($this->pow->verify($state, "%%%not-base64%%%"));

        $this->pow->issueChallenge($state);
        $this->assertFalse($this->pow->verify($state, base64_encode("not json")));

        $this->pow->issueChallenge($state);
        $this->assertFalse($this->pow->verify($state, base64_encode("[1,2]")));

        $this->pow->issueChallenge($state);
        $this->assertFalse($this->pow->verify($state, str_repeat("A", 5000)));
    }

    public function testResetSecretVoidsTheOpenChallenge(): void
    {
        $state = $this->makeState();
        $encoded = $this->solve($this->pow->issueChallenge($state))->toBase64();
        $this->pow->resetSecret($state);

        $this->assertFalse($this->pow->verify($state, $encoded));
    }

    public function testDefaultDifficultyIsConservative(): void
    {
        $this->assertLessThanOrEqual(2000, \ilAuthGuardProofOfWork::COST);
        $this->assertLessThanOrEqual(3000, \ilAuthGuardProofOfWork::COUNTER_MAX);
        $this->assertLessThan(
            \ilAuthGuardProofOfWork::COUNTER_MAX,
            \ilAuthGuardProofOfWork::COUNTER_MIN
        );
    }
}
