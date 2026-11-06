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
 * Description of one setting of a challenge provider, enough for the
 * configuration screen to draw it and for the settings to store it.
 */
final class ilAuthGuardProviderField
{
    /** @var string plain text, stored as given */
    public const TYPE_TEXT = "text";

    /** @var string never shown again, stored encrypted */
    public const TYPE_SECRET = "secret";

    /** @var string one of a fixed list of values */
    public const TYPE_SELECT = "select";

    /** @var string name inside the provider, lowercase letters and "_" */
    public readonly string $name;

    /** @var string one of the TYPE_ constants */
    public readonly string $type;

    /** @var string lang key of the label */
    public readonly string $label_key;

    /** @var string lang key of the byline, empty for none */
    public readonly string $info_key;

    /** @var string lang key of the message shown when the value is refused */
    public readonly string $error_key;

    /** @var array<string, string> lang key of the title by value, for TYPE_SELECT */
    public readonly array $options;

    /** @var string value shown and used while nothing is stored */
    public readonly string $default;

    /** @var int */
    public readonly int $max_length;

    /**
     * @param string $name
     * @param string $type one of the TYPE_ constants
     * @param string $label_key
     * @param string $error_key
     * @param string $info_key
     * @param array<string, string> $options
     * @param string $default
     * @param int $max_length
     * @return void
     */
    public function __construct(
        string $name,
        string $type,
        string $label_key,
        string $error_key,
        string $info_key = "",
        array $options = [],
        string $default = "",
        int $max_length = 100
    ) {
        $this->name = $name;
        $this->type = $type;
        $this->label_key = $label_key;
        $this->error_key = $error_key;
        $this->info_key = $info_key;
        $this->options = $options;
        $this->default = $default;
        $this->max_length = $max_length;
    }

    /**
     * @return bool
     */
    public function isSecret(): bool
    {
        return $this->type === self::TYPE_SECRET;
    }

    /**
     * The name of the form input, which is also the key under which the
     * value is stored: "<provider id>_<field name>".
     *
     * @param string $provider_id
     * @return string
     */
    public function getPostVar(string $provider_id): string
    {
        return $provider_id . "_" . $this->name;
    }
}
