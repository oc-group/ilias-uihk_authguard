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

use Psr\Http\Message\ServerRequestInterface;

/**
 * Public entry point other plugins call to protect a form: render() returns
 * the markup for inside the form, verify() checks the submit.
 *
 * @api
 */
class ilAuthGuardFormProtection
{
    /** @var int raised on a breaking change of this class */
    public const API_VERSION = 1;

    /** @var string POST field the proof-of-work widget fills */
    public const FIELD_POW = "authguard_pow";

    /** @var string POST field of the image CAPTCHA fallback */
    public const FIELD_CAPTCHA = "captcha_code";

    /** @var string POST field the Google reCAPTCHA widget fills */
    public const FIELD_RECAPTCHA = "g-recaptcha-response";

    /** @var float minimum seconds between render and submit; may be fractional */
    public const MIN_SUBMIT_INTERVAL_SECONDS = 2.0;

    /** @var string */
    private const WIDGET_SCRIPT = "/js/authguard-widget.js";

    /** @var string */
    private const RECAPTCHA_SCRIPT = "/js/authguard-recaptcha.js";

    /** @var array<string, string[]> template variables that belong to a provider's block */
    private const BLOCK_VARIABLES = [
        ilAuthGuardSettings::PROVIDER_ALTCHA => ["CHALLENGE_URL", "POW_FIELD", "WIDGET_SCRIPT_URL"],
        ilAuthGuardSettings::PROVIDER_RECAPTCHA => ["RECAPTCHA_SITE_KEY", "RECAPTCHA_SCRIPT_URL"],
    ];

    /** @var ilAuthGuardSessionStore */
    private ilAuthGuardSessionStore $store;

    /** @var ilAuthGuardProofOfWork|null built on first use */
    private ?ilAuthGuardProofOfWork $pow;

    /** @var \ilLogger|null fetched on first use */
    private ?\ilLogger $logger;

    /** @var ilAuthGuardSettings|null built on first use */
    private ?ilAuthGuardSettings $settings;

    /** @var ilAuthGuardRecaptcha|null built on first use */
    private ?ilAuthGuardRecaptcha $recaptcha;

    /**
     * @param ilAuthGuardSessionStore|null $store
     * @param ilAuthGuardProofOfWork|null $pow
     * @param \ilLogger|null $logger
     * @param ilAuthGuardSettings|null $settings
     * @param ilAuthGuardRecaptcha|null $recaptcha
     * @return void
     */
    public function __construct(
        ?ilAuthGuardSessionStore $store = null,
        ?ilAuthGuardProofOfWork $pow = null,
        ?\ilLogger $logger = null,
        ?ilAuthGuardSettings $settings = null,
        ?ilAuthGuardRecaptcha $recaptcha = null
    ) {
        $this->store = $store ?? new ilAuthGuardSessionStore();
        $this->pow = $pow;
        $this->logger = $logger;
        $this->settings = $settings;
        $this->recaptcha = $recaptcha;
    }

    /**
     * True when the plugin is installed and active and this class offers at
     * least the requested API version. Never throws, so a consumer can call
     * it whatever the plugin state.
     *
     * @param int $min_version
     * @return bool
     */
    public static function isAvailable(int $min_version = 1): bool
    {
        global $DIC;

        if (self::API_VERSION < $min_version) {
            return false;
        }

        // isDependencyAvailable() calls a method named like the id, which does
        // not exist for "component.repository" and throws an Error.
        try {
            if (!isset($DIC["component.repository"])) {
                return false;
            }

            /** @var \ilComponentRepository $repository */
            $repository = $DIC["component.repository"];

            return $repository->hasPluginId(ilAuthGuardPlugin::PLUGIN_ID)
                && $repository->getPluginById(ilAuthGuardPlugin::PLUGIN_ID)->isActive();
        } catch (\Throwable $e) {
            return false;
        }
    }

    /**
     * Returns the HTML to place inside the form and records the state the
     * verification later needs. A new render replaces the state of the
     * previous one for the same form id.
     *
     * @param string $form_id lowercase letters, digits, "_" and "-", 1 to 64
     * @throws InvalidArgumentException when the form id has the wrong shape
     * @return string
     */
    public function render(string $form_id): string
    {
        $state = $this->createState($form_id);

        $honeypot_name = ilAuthGuardHoneypot::generateName();

        $state->clearAll();
        $state->set(ilAuthGuardFormState::FIELD_RENDERED_AT, $this->now());
        $state->set(ilAuthGuardFormState::FIELD_HONEYPOT, $honeypot_name);

        $provider = $this->resolveProvider();
        if ($provider === ilAuthGuardSettings::PROVIDER_ALTCHA) {
            $this->getProofOfWork()->resetSecret($state);
        }

        $this->registerAssets();

        return $this->renderMarkup([
            "PROVIDER" => $provider,
            "RECAPTCHA_SITE_KEY" => $provider === ilAuthGuardSettings::PROVIDER_RECAPTCHA
                ? $this->getSettings()->getRecaptchaSiteKey()
                : "",
            "RECAPTCHA_SCRIPT_URL" => $this->getAssetUrl(self::RECAPTCHA_SCRIPT),
            "FORM_ID" => $form_id,
            "HONEYPOT_NAME" => $honeypot_name,
            "POW_FIELD" => self::FIELD_POW,
            "CAPTCHA_FIELD" => self::FIELD_CAPTCHA,
            "CHALLENGE_URL" => $this->getEndpointUrl(ilAuthGuardGUI::CMD_CHALLENGE, $form_id),
            "IMAGE_URL" => $this->getEndpointUrl(ilAuthGuardGUI::CMD_SHOW_IMAGE, $form_id),
            "WIDGET_SCRIPT_URL" => $this->getAssetUrl(self::WIDGET_SCRIPT),
        ]);
    }

    /**
     * Checks a submit and consumes the form's state, whatever the outcome.
     * Order: timing, honeypot, the selected challenge (Altcha proof-of-work
     * or Google reCAPTCHA), then the image CAPTCHA when no answer to that
     * challenge came in. Every rejection carries the same message.
     *
     * @param string $form_id the id given to render()
     * @param ServerRequestInterface $request
     * @throws InvalidArgumentException when the form id has the wrong shape
     * @return ilAuthGuardVerificationResult
     */
    public function verify(
        string $form_id,
        ServerRequestInterface $request
    ): ilAuthGuardVerificationResult {
        $state = $this->createState($form_id);

        $parsed_body = $request->getParsedBody();
        $body = is_array($parsed_body) ? $parsed_body : [];

        try {
            $result = $this->evaluate($state, $body);
        } finally {
            $state->clearAll();
        }

        if (!$result->isPassed()) {
            $this->getLogger()->warning(
                "AuthGuard: submit rejected (form: " . $form_id
                . ", reason: " . $result->getReason() . ")"
            );
        }

        return $result;
    }

    /**
     * @param ilAuthGuardFormState $state
     * @param array<mixed> $body
     * @return ilAuthGuardVerificationResult
     */
    private function evaluate(
        ilAuthGuardFormState $state,
        array $body
    ): ilAuthGuardVerificationResult {
        $rendered_at = $state->get(ilAuthGuardFormState::FIELD_RENDERED_AT);
        $honeypot_name = (string) $state->get(ilAuthGuardFormState::FIELD_HONEYPOT);

        if ($rendered_at === null || $honeypot_name === "") {
            return $this->fail(ilAuthGuardVerificationResult::REASON_MISSING_STATE);
        }

        if (($this->now() - (float) $rendered_at) < self::MIN_SUBMIT_INTERVAL_SECONDS) {
            return $this->fail(ilAuthGuardVerificationResult::REASON_TIMING);
        }

        if (ilAuthGuardHoneypot::isTripped($body, $honeypot_name)) {
            return $this->fail(ilAuthGuardVerificationResult::REASON_HONEYPOT);
        }

        if ($this->resolveProvider() === ilAuthGuardSettings::PROVIDER_RECAPTCHA) {
            return $this->evaluateRecaptcha($state, $body);
        }

        $pow_payload = $this->readString($body, self::FIELD_POW);
        if ($pow_payload !== "") {
            if ($this->getProofOfWork()->verify($state, $pow_payload)) {
                return ilAuthGuardVerificationResult::passed();
            }

            return $this->fail(ilAuthGuardVerificationResult::REASON_POW);
        }

        return $this->evaluateCaptcha($state, $body);
    }

    /**
     * A present reCAPTCHA answer is checked with Google and never falls
     * through to the image CAPTCHA; an absent one means a visitor without
     * JavaScript, who gets the image CAPTCHA.
     *
     * @param ilAuthGuardFormState $state
     * @param array<mixed> $body
     * @return ilAuthGuardVerificationResult
     */
    private function evaluateRecaptcha(
        ilAuthGuardFormState $state,
        array $body
    ): ilAuthGuardVerificationResult {
        $answer = $this->readString($body, self::FIELD_RECAPTCHA);
        if ($answer === "") {
            return $this->evaluateCaptcha($state, $body);
        }

        if ($this->getRecaptcha()->verify($answer)) {
            return ilAuthGuardVerificationResult::passed();
        }

        return $this->fail(ilAuthGuardVerificationResult::REASON_RECAPTCHA);
    }

    /**
     * @param ilAuthGuardFormState $state
     * @param array<mixed> $body
     * @return ilAuthGuardVerificationResult
     */
    private function evaluateCaptcha(
        ilAuthGuardFormState $state,
        array $body
    ): ilAuthGuardVerificationResult {
        $submitted = $this->readString($body, self::FIELD_CAPTCHA);
        $expected = (string) $state->get(ilAuthGuardFormState::FIELD_PHRASE);

        // No phrase means no image was ever requested: the visitor runs
        // JavaScript and submitted before the widget had finished.
        if (trim($expected) === "") {
            return $this->fail(ilAuthGuardVerificationResult::REASON_CAPTCHA);
        }

        if (trim($submitted) === "") {
            return $this->fail(ilAuthGuardVerificationResult::REASON_CAPTCHA);
        }

        if (!ilAuthGuardHelper::isValid($submitted, $expected)) {
            return $this->fail(ilAuthGuardVerificationResult::REASON_CAPTCHA);
        }

        return ilAuthGuardVerificationResult::passed();
    }

    /**
     * @param array<mixed> $body
     * @param string $field
     * @return string empty when absent or not a string
     */
    private function readString(array $body, string $field): string
    {
        $value = $body[$field] ?? "";

        return is_string($value) ? $value : "";
    }

    /**
     * Every rejection shows the visitor the same text, so a script that
     * retries cannot learn which check it failed. The reason goes only to
     * the log and to the caller.
     *
     * @param string $reason
     * @return ilAuthGuardVerificationResult
     */
    private function fail(string $reason): ilAuthGuardVerificationResult
    {
        return ilAuthGuardVerificationResult::failed($reason, $this->translate("security_check_failed"));
    }

    /**
     * The challenge provider in force: reCAPTCHA only when its keys are
     * complete, otherwise Altcha.
     *
     * @return string one of the ilAuthGuardSettings::PROVIDER_ constants
     */
    private function resolveProvider(): string
    {
        $settings = $this->getSettings();
        $provider = $settings->getEffectiveProvider();

        if ($provider !== $settings->getProvider()) {
            $this->getLogger()->error(
                "AuthGuard: Google reCAPTCHA is selected but its keys are incomplete; "
                . "the Altcha check is used instead."
            );
        }

        return $provider;
    }

    /**
     * @return ilAuthGuardSettings
     */
    private function getSettings(): ilAuthGuardSettings
    {
        if ($this->settings === null) {
            $this->settings = new ilAuthGuardSettings();
        }

        return $this->settings;
    }

    /**
     * @return ilAuthGuardRecaptcha
     */
    private function getRecaptcha(): ilAuthGuardRecaptcha
    {
        if ($this->recaptcha === null) {
            $this->recaptcha = new ilAuthGuardRecaptcha($this->getSettings(), $this->getLogger());
        }

        return $this->recaptcha;
    }

    /**
     * @param string $form_id
     * @throws InvalidArgumentException when the form id has the wrong shape
     * @return ilAuthGuardFormState
     */
    private function createState(string $form_id): ilAuthGuardFormState
    {
        return new ilAuthGuardFormState($this->store, $form_id);
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

    /**
     * @return \ilLogger
     */
    private function getLogger(): \ilLogger
    {
        global $DIC;

        if ($this->logger === null) {
            $this->logger = $DIC->logger()->root();
        }

        return $this->logger;
    }

    /**
     * @return float
     */
    protected function now(): float
    {
        return microtime(true);
    }

    /**
     * @param string $lang_key
     * @return string
     */
    protected function translate(string $lang_key): string
    {
        return ilAuthGuardPlugin::getInstance()->txt($lang_key);
    }

    /**
     * @param string $command
     * @param string $form_id
     * @return string
     */
    protected function getEndpointUrl(string $command, string $form_id): string
    {
        global $DIC;

        return $DIC->ctrl()->getLinkTargetByClass(
            [ilUIPluginRouterGUI::class, ilAuthGuardGUI::class],
            $command
        ) . "&" . ilAuthGuardGUI::PARAM_FORM_ID . "=" . rawurlencode($form_id);
    }

    /**
     * @param string $path starting with a slash, relative to the plugin
     * @return string
     */
    protected function getAssetUrl(string $path): string
    {
        $base = defined("ILIAS_HTTP_PATH") ? ILIAS_HTTP_PATH . "/" : "";

        return $base . ilAuthGuardPlugin::getInstance()->getRelativeDirectory() . $path;
    }

    /**
     * Loads the stylesheet of the fallback block.
     *
     * @return void
     */
    protected function registerAssets(): void
    {
        global $DIC;

        $DIC->ui()->mainTemplate()->addCss(
            ilAuthGuardPlugin::getInstance()->getRelativeDirectory() . "/css/captcha.css"
        );
    }

    /**
     * @param array<string, string> $variables template placeholders by name
     * @return string
     */
    protected function renderMarkup(array $variables): string
    {
        $plugin = ilAuthGuardPlugin::getInstance();
        $tpl = $plugin->getTemplate("default/tpl.form_protection.html");

        $variables["CAPTCHA_ALT"] = $plugin->txt("captcha_alt");
        $variables["CAPTCHA_LABEL"] = $plugin->txt("captcha_label");
        $variables["CAPTCHA_INFO"] = $plugin->txt("captcha_info");
        $variables["WIDGET_LABEL"] = $plugin->txt("widget_label");

        $provider = $variables["PROVIDER"] ?? ilAuthGuardSettings::PROVIDER_ALTCHA;
        unset($variables["PROVIDER"]);
        if ($provider !== ilAuthGuardSettings::PROVIDER_RECAPTCHA) {
            $provider = ilAuthGuardSettings::PROVIDER_ALTCHA;
        }

        // A template block is output once any of its variables is set, so
        // only the selected provider's block gets values.
        $other_block = self::BLOCK_VARIABLES[$provider === ilAuthGuardSettings::PROVIDER_RECAPTCHA
            ? ilAuthGuardSettings::PROVIDER_ALTCHA
            : ilAuthGuardSettings::PROVIDER_RECAPTCHA];

        foreach ($variables as $name => $value) {
            if (!in_array($name, $other_block, true)) {
                $tpl->setVariable($name, htmlspecialchars($value, ENT_QUOTES, "UTF-8"));
            }
        }

        $tpl->setCurrentBlock($provider);
        $tpl->parseCurrentBlock();

        return $tpl->get();
    }
}
