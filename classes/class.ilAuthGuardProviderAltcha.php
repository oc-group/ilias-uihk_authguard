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

/**
 * The default provider: an Altcha proof of work that runs on this server
 * and in the visitor's browser. It needs no settings and sends nothing to
 * a third party.
 */
class ilAuthGuardProviderAltcha implements ilAuthGuardChallengeProvider
{
    /** @var string */
    public const ID = "altcha";

    /** @var string */
    private const WIDGET_SCRIPT = "/js/authguard-widget.js";

    /** @var ilAuthGuardProofOfWork|null built on first use */
    private ?ilAuthGuardProofOfWork $pow;

    /**
     * @param ilAuthGuardProofOfWork|null $pow
     * @return void
     */
    public function __construct(?ilAuthGuardProofOfWork $pow = null)
    {
        $this->pow = $pow;
    }

    /**
     * @return string
     */
    public function getId(): string
    {
        return self::ID;
    }

    /**
     * @return bool
     */
    public function isExternal(): bool
    {
        return false;
    }

    /**
     * @return string
     */
    public function getPostField(): string
    {
        return ilAuthGuardFormProtection::FIELD_POW;
    }

    /**
     * @return string
     */
    public function getFailureReason(): string
    {
        return ilAuthGuardVerificationResult::REASON_POW;
    }

    /**
     * @return string[]
     */
    public function getBlockVariables(): array
    {
        return ["CHALLENGE_URL", "POW_FIELD", "WIDGET_SCRIPT_URL"];
    }

    /**
     * @return ilAuthGuardProviderField[]
     */
    public function getSettingsFields(): array
    {
        return [];
    }

    /**
     * @param ilAuthGuardSettings $settings
     * @return bool
     */
    public function isConfigured(ilAuthGuardSettings $settings): bool
    {
        return true;
    }

    /**
     * @param array<string, string> $values
     * @param array<string, bool> $secrets_stored
     * @return array<string, string>
     */
    public function validate(array $values, array $secrets_stored): array
    {
        return [];
    }

    /**
     * Starts a fresh proof-of-work secret for the form.
     *
     * @param ilAuthGuardProviderContext $context
     * @return void
     */
    public function prepare(ilAuthGuardProviderContext $context): void
    {
        $this->getProofOfWork()->resetSecret($context->state);
    }

    /**
     * @param ilAuthGuardProviderContext $context
     * @return array<string, string>
     */
    public function getRenderVariables(ilAuthGuardProviderContext $context): array
    {
        return [
            "CHALLENGE_URL" => $context->getEndpointUrl(ilAuthGuardGUI::CMD_CHALLENGE),
            "POW_FIELD" => $this->getPostField(),
            "WIDGET_SCRIPT_URL" => $context->getAssetUrl(self::WIDGET_SCRIPT),
        ];
    }

    /**
     * @param string $answer
     * @param ilAuthGuardProviderContext $context
     * @return string
     */
    public function check(string $answer, ilAuthGuardProviderContext $context): string
    {
        return $this->getProofOfWork()->verify($context->state, $answer)
            ? self::OUTCOME_PASSED
            : self::OUTCOME_REJECTED;
    }

    /**
     * @return ilAuthGuardProofOfWork
     */
    private function getProofOfWork(): ilAuthGuardProofOfWork
    {
        if ($this->pow === null) {
            $this->pow = new ilAuthGuardProofOfWork();
        }

        return $this->pow;
    }
}
