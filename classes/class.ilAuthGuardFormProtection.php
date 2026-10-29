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

    /** @var float minimum seconds between render and submit; may be fractional */
    public const MIN_SUBMIT_INTERVAL_SECONDS = 2.0;

    /** @var string */
    private const WIDGET_SCRIPT = "/node_modules/altcha/dist/main/altcha.i18n.min.js";

    /** @var ilAuthGuardSessionStore */
    private ilAuthGuardSessionStore $store;

    /** @var ilAuthGuardProofOfWork|null built on first use */
    private ?ilAuthGuardProofOfWork $pow;

    /** @var \ilLogger|null fetched on first use */
    private ?\ilLogger $logger;

    /**
     * @param ilAuthGuardSessionStore|null $store
     * @param ilAuthGuardProofOfWork|null $pow
     * @param \ilLogger|null $logger
     * @return void
     */
    public function __construct(
        ?ilAuthGuardSessionStore $store = null,
        ?ilAuthGuardProofOfWork $pow = null,
        ?\ilLogger $logger = null
    ) {
        $this->store = $store ?? new ilAuthGuardSessionStore();
        $this->pow = $pow;
        $this->logger = $logger;
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
        $this->getProofOfWork()->resetSecret($state);

        $this->registerAssets();

        return $this->renderMarkup([
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
     * Order: timing, honeypot, proof-of-work, then the image CAPTCHA when no
     * proof-of-work payload came in.
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
            return $this->fail(
                ilAuthGuardVerificationResult::REASON_MISSING_STATE,
                "form_state_missing"
            );
        }

        if (($this->now() - (float) $rendered_at) < self::MIN_SUBMIT_INTERVAL_SECONDS) {
            return $this->fail(
                ilAuthGuardVerificationResult::REASON_TIMING,
                "submit_too_fast"
            );
        }

        if (ilAuthGuardHoneypot::isTripped($body, $honeypot_name)) {
            return $this->fail(
                ilAuthGuardVerificationResult::REASON_HONEYPOT,
                "security_check_failed"
            );
        }

        $pow_payload = $this->readString($body, self::FIELD_POW);
        if ($pow_payload !== "") {
            if ($this->getProofOfWork()->verify($state, $pow_payload)) {
                return ilAuthGuardVerificationResult::passed();
            }

            return $this->fail(
                ilAuthGuardVerificationResult::REASON_POW,
                "pow_failed"
            );
        }

        return $this->evaluateCaptcha($state, $body);
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
            return $this->fail(
                ilAuthGuardVerificationResult::REASON_CAPTCHA,
                "pow_missing"
            );
        }

        if (trim($submitted) === "") {
            return $this->fail(
                ilAuthGuardVerificationResult::REASON_CAPTCHA,
                "captcha_required"
            );
        }

        if (!ilAuthGuardHelper::isValid($submitted, $expected)) {
            return $this->fail(
                ilAuthGuardVerificationResult::REASON_CAPTCHA,
                "captcha_validation_failed"
            );
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
     * @param string $reason
     * @param string $lang_key
     * @return ilAuthGuardVerificationResult
     */
    private function fail(string $reason, string $lang_key): ilAuthGuardVerificationResult
    {
        return ilAuthGuardVerificationResult::failed($reason, $this->translate($lang_key));
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

        foreach ($variables as $name => $value) {
            $tpl->setVariable($name, htmlspecialchars($value, ENT_QUOTES, "UTF-8"));
        }

        return $tpl->get();
    }
}
