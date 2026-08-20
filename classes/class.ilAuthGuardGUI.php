<?php

/**
 * This file is part of AuthGuard Plugin for ILIAS,
 * developed by OC Open Consulting to block automated self-registration
 * submissions with a local image CAPTCHA.
 *
 * @author Dienifer Mendonça <dienifer@oc-group.eu>
 * @copyright 2026 OC Open Consulting SB Srl
 * @license http://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */

declare(strict_types=1);

/**
 * Serves the CAPTCHA puzzle image and stores the expected phrase in the
 * session. Routed via ilUIPluginRouterGUI, reachable anonymously: this is
 * the self-registration page, before any account exists.
 *
 * @ilCtrl_isCalledBy ilAuthGuardGUI: ilAuthGuardUIHookGUI, ilUIPluginRouterGUI
 */
class ilAuthGuardGUI
{
    /** @var string generate and stream a fresh CAPTCHA image */
    public const CMD_SHOW_IMAGE = "showImage";

    /** @var float minimum seconds between two image regenerations for the same session; may be fractional */
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
     * Delegates incoming commands. An inactive plugin and an unknown command
     * both answer a plain 404 rather than a rendered ILIAS error page: this is
     * an anonymously reachable image endpoint, not a screen.
     *
     * @return void
     */
    public function executeCommand(): void
    {
        if (!$this->plugin->isActive()) {
            ilAuthGuardHelper::respondNotFound();
        }

        $cmd = $this->ctrl->getCmd(self::CMD_SHOW_IMAGE);

        switch ($cmd) {
            case self::CMD_SHOW_IMAGE:
                $this->$cmd();
                break;

            default:
                ilAuthGuardHelper::respondNotFound();
        }
    }

    /**
     * Generates a fresh puzzle, stores its phrase in the session and delivers
     * the image. Every call regenerates the phrase, which is how the widget's
     * reload control works. The throttle applies only when the session already
     * holds a phrase, so a first image is never denied.
     *
     * @return never
     */
    protected function showImage(): never
    {
        $last_generation = ilAuthGuardHelper::readLastGenerationTime();
        $now = microtime(true);
        $has_phrase = ilAuthGuardHelper::readExpectedPhrase() !== "";

        if (
            $has_phrase
            && $last_generation !== null
            && ($now - $last_generation) < self::MIN_REGENERATION_INTERVAL_SECONDS
        ) {
            ilAuthGuardHelper::respondTooManyRequests(
                max(1, (int) ceil(self::MIN_REGENERATION_INTERVAL_SECONDS))
            );
        }

        $builder = new \Gregwar\Captcha\CaptchaBuilder();
        $builder->build();

        ilAuthGuardHelper::storeExpectedPhrase($builder->getPhrase());
        ilAuthGuardHelper::storeLastGenerationTime($now);

        $image_type = $builder->getImageType();

        // Not via $DIC->fileDelivery(), which cannot be kept from caching the
        // puzzle on every supported version.
        ilAuthGuardHelper::respondWithUncacheableImage(
            $builder->get(),
            "image/" . $image_type,
            "captcha." . $image_type
        );
    }
}
