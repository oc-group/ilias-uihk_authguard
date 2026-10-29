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

use AltchaOrg\Altcha\Algorithm\Pbkdf2;
use AltchaOrg\Altcha\Altcha;
use AltchaOrg\Altcha\CreateChallengeOptions;
use AltchaOrg\Altcha\Payload;
use AltchaOrg\Altcha\VerifySolutionOptions;

/**
 * Issues and verifies Altcha proof-of-work challenges. The signing keys
 * derive from a secret held in the session, so nothing is persisted and a
 * challenge is only valid for the session that fetched it.
 */
class ilAuthGuardProofOfWork
{
    /** @var int PBKDF2 iterations per attempt the browser makes */
    public const COST = 2000;

    /** @var int lowest number of attempts a challenge can require */
    public const COUNTER_MIN = 500;

    /** @var int highest number of attempts a challenge can require */
    public const COUNTER_MAX = 1500;

    /** @var int seconds a challenge stays valid */
    public const TTL_SECONDS = 3600;

    /** @var int longest accepted payload, in characters */
    public const MAX_PAYLOAD_LENGTH = 4096;

    /** @var int */
    private int $cost;

    /** @var int */
    private int $counter_min;

    /** @var int */
    private int $counter_max;

    /**
     * @param int $cost
     * @param int $counter_min
     * @param int $counter_max
     * @return void
     */
    public function __construct(
        int $cost = self::COST,
        int $counter_min = self::COUNTER_MIN,
        int $counter_max = self::COUNTER_MAX
    ) {
        require_once __DIR__ . "/../vendor/autoload.php";

        $this->cost = $cost;
        $this->counter_min = $counter_min;
        $this->counter_max = $counter_max;
    }

    /**
     * Starts a fresh secret for the form, which voids every challenge issued
     * under the previous one.
     *
     * @param ilAuthGuardFormState $state
     * @return void
     */
    public function resetSecret(ilAuthGuardFormState $state): void
    {
        $state->set(ilAuthGuardFormState::FIELD_POW_SECRET, bin2hex(random_bytes(32)));
        $state->clear(ilAuthGuardFormState::FIELD_POW_CHALLENGE);
    }

    /**
     * Creates a challenge and remembers its signature as the one open
     * challenge of the form; an earlier one stops being valid.
     *
     * @param ilAuthGuardFormState $state
     * @return array<string, mixed> the JSON document the widget expects
     */
    public function issueChallenge(ilAuthGuardFormState $state): array
    {
        if ((string) $state->get(ilAuthGuardFormState::FIELD_POW_SECRET) === "") {
            $this->resetSecret($state);
        }

        $challenge = $this->createClient($state)->createChallenge(
            new CreateChallengeOptions(
                algorithm: new Pbkdf2(),
                cost: $this->cost,
                counter: random_int($this->counter_min, $this->counter_max),
                expiresAt: time() + self::TTL_SECONDS
            )
        );

        $state->set(
            ilAuthGuardFormState::FIELD_POW_CHALLENGE,
            (string) $challenge->signature
        );

        return $challenge->toArray();
    }

    /**
     * Checks a payload posted by the widget. The open challenge is consumed
     * first, so no payload can be tried twice, whatever the outcome.
     *
     * @param ilAuthGuardFormState $state
     * @param string $raw the base64 payload from the request
     * @return bool
     */
    public function verify(ilAuthGuardFormState $state, string $raw): bool
    {
        $open_signature = (string) $state->get(ilAuthGuardFormState::FIELD_POW_CHALLENGE);
        $state->clear(ilAuthGuardFormState::FIELD_POW_CHALLENGE);

        if ($open_signature === "" || strlen($raw) > self::MAX_PAYLOAD_LENGTH) {
            return false;
        }

        try {
            $payload = Payload::fromBase64($raw);
        } catch (\InvalidArgumentException | \TypeError) {
            return false;
        }

        if (!hash_equals($open_signature, (string) $payload->challenge->signature)) {
            return false;
        }

        $result = $this->createClient($state)->verifySolution(
            new VerifySolutionOptions($payload, new Pbkdf2())
        );

        return $result->verified;
    }

    /**
     * @param ilAuthGuardFormState $state
     * @return Altcha
     */
    private function createClient(ilAuthGuardFormState $state): Altcha
    {
        $secret = (string) $state->get(ilAuthGuardFormState::FIELD_POW_SECRET);

        return new Altcha(
            hmacSignatureSecret: hash_hmac("sha256", "signature", $secret),
            hmacKeySignatureSecret: hash_hmac("sha256", "key", $secret)
        );
    }
}
