<?php

/**
 * This file is part of AuthGuard Plugin for ILIAS,
 * developed by OC Open Consulting to block automated self-registration
 * submissions with a local image CAPTCHA.
 *
 * @author Dienifer Mendonça <dienifer@oc-group.eu>
 * @author Vincenzo Padula <vincenzo@oc-group.eu>
 * @copyright 2026 OC Open Consulting SB Srl
 * @license http://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */

declare(strict_types=1);

/**
 * Anonymous endpoints of the widget: the CAPTCHA puzzle image and the
 * proof-of-work challenge. Routed via ilUIPluginRouterGUI, reachable before
 * any account exists. Both need a form the session has rendered.
 *
 * @ilCtrl_isCalledBy ilAuthGuardGUI: ilAuthGuardUIHookGUI, ilUIPluginRouterGUI
 */
class ilAuthGuardGUI
{
    /** @var string generate and stream a fresh CAPTCHA image */
    public const CMD_SHOW_IMAGE = "showImage";

    /** @var string issue a proof-of-work challenge as JSON */
    public const CMD_CHALLENGE = "challenge";

    /** @var string query parameter naming the protected form */
    public const PARAM_FORM_ID = "form_id";

    /** @var float minimum seconds between two image regenerations for the same form; may be fractional */
    public const MIN_REGENERATION_INTERVAL_SECONDS = 1.0;

    /** @var ilCtrlInterface */
    protected ilCtrlInterface $ctrl;

    /** @var ilAuthGuardPlugin */
    protected ilAuthGuardPlugin $plugin;

    /**
     * Loads the plugin's own Composer autoloader here rather than at plugin
     * init, which runs on every page load and must stay cheap: only this
     * class needs the CAPTCHA library.
     *
     * @return void
     */
    public function __construct()
    {
        global $DIC;

        $this->ctrl = $DIC->ctrl();

        $this->plugin = ilAuthGuardPlugin::getInstance();

        require_once __DIR__ . "/../vendor/autoload.php";
    }

    /**
     * Delegates incoming commands. An inactive plugin, an unknown command and
     * a form id the session has not rendered all answer a plain 404 rather
     * than a rendered ILIAS error page: these are anonymously reachable
     * endpoints, not screens.
     *
     * @return void
     */
    public function executeCommand(): void
    {
        if (!$this->plugin->isActive()) {
            ilAuthGuardHelper::respondNotFound();
        }

        $cmd = $this->ctrl->getCmd(self::CMD_SHOW_IMAGE);

        match ($cmd) {
            self::CMD_SHOW_IMAGE => $this->showImage($this->loadRenderedState()),
            self::CMD_CHALLENGE => $this->challenge($this->loadRenderedState()),
            default => ilAuthGuardHelper::respondNotFound(),
        };
    }

    /**
     * Reads the form id from the query and returns its state, ending the
     * request with a 404 when the id is missing, malformed or was never
     * rendered in this session.
     *
     * @return ilAuthGuardFormState
     */
    protected function loadRenderedState(): ilAuthGuardFormState
    {
        global $DIC;

        $query = $DIC->http()->wrapper()->query();
        $form_id = "";
        if ($query->has(self::PARAM_FORM_ID)) {
            try {
                $form_id = $query->retrieve(
                    self::PARAM_FORM_ID,
                    $DIC->refinery()->kindlyTo()->string()
                );
            } catch (\UnexpectedValueException) {
                $form_id = "";
            }
        }

        if (!ilAuthGuardFormState::isValidFormId($form_id)) {
            ilAuthGuardHelper::respondNotFound();
        }

        $state = new ilAuthGuardFormState(new ilAuthGuardSessionStore(), $form_id);
        if (!$state->isRendered()) {
            ilAuthGuardHelper::respondNotFound();
        }

        return $state;
    }

    /**
     * Generates a fresh puzzle, stores its phrase in the session and delivers
     * the image. Every call regenerates the phrase. The throttle applies only
     * when the form already holds a phrase, so a first image is never denied.
     *
     * @param ilAuthGuardFormState $state
     * @return never
     */
    protected function showImage(ilAuthGuardFormState $state): never
    {
        $last_generation = $state->get(ilAuthGuardFormState::FIELD_LAST_GENERATION);
        $now = microtime(true);
        $has_phrase = (string) $state->get(ilAuthGuardFormState::FIELD_PHRASE) !== "";

        if (
            $has_phrase
            && $last_generation !== null
            && ($now - (float) $last_generation) < self::MIN_REGENERATION_INTERVAL_SECONDS
        ) {
            ilAuthGuardHelper::respondTooManyRequests(
                max(1, (int) ceil(self::MIN_REGENERATION_INTERVAL_SECONDS))
            );
        }

        $builder = new \Gregwar\Captcha\CaptchaBuilder();
        $builder->build();

        $state->set(ilAuthGuardFormState::FIELD_PHRASE, $builder->getPhrase());
        $state->set(ilAuthGuardFormState::FIELD_LAST_GENERATION, $now);

        $image_type = $builder->getImageType();

        // Not via $DIC->fileDelivery(), which cannot be kept from caching the
        // puzzle on every supported version.
        ilAuthGuardHelper::respondUncacheable(
            $builder->get(),
            "image/" . $image_type,
            'inline; filename="captcha.' . $image_type . '"'
        );
    }

    /**
     * Issues a proof-of-work challenge for the form. The previously open
     * challenge of the form stops being valid.
     *
     * @param ilAuthGuardFormState $state
     * @return never
     */
    protected function challenge(ilAuthGuardFormState $state): never
    {
        $challenge = (new ilAuthGuardProofOfWork())->issueChallenge($state);

        ilAuthGuardHelper::respondUncacheable(
            json_encode($challenge, JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES),
            "application/json",
            null
        );
    }
}
