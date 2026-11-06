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

/**
 * A template object for the unit tests: the ILIAS template engine without an
 * initialised ILIAS. Unknown variables are kept, empty blocks removed and
 * use_preg is off after loading, as for a plugin template in production. The
 * engine caches are skipped, since they need an initialised ILIAS.
 */
class PlainTemplate extends \HTML_Template_IT
{
    /**
     * @param string $path absolute path of the template file
     * @return self
     */
    public static function load(string $path): self
    {
        $had_dic = array_key_exists("DIC", $GLOBALS);
        $saved_dic = $GLOBALS["DIC"] ?? null;
        $GLOBALS["DIC"] = new \ILIAS\DI\Container();

        try {
            $tpl = new self();
            $tpl->loadTemplatefile($path, false, true);
            $tpl->setOption("use_preg", false);
        } finally {
            if ($had_dic) {
                $GLOBALS["DIC"] = $saved_dic;
            } else {
                unset($GLOBALS["DIC"]);
            }
        }

        return $tpl;
    }

    /**
     * @return void
     */
    protected function init(): void
    {
        $this->free();
        $this->findBlocks($this->template);
        $this->buildBlockvariablelist();
        $this->template = "";
    }
}
