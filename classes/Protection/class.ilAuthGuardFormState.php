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
 * The session values of one protected form, namespaced by form id so that
 * two forms in one session never share a key.
 */
class ilAuthGuardFormState
{
    /** @var string */
    public const FORM_ID_PATTERN = "/^[a-z0-9_-]{1,64}$/D";

    /** @var string microtime(true) of the render that placed the widget */
    public const FIELD_RENDERED_AT = "rendered_at";

    /** @var string name of the honeypot input of the current render */
    public const FIELD_HONEYPOT = "honeypot";

    /** @var string hex secret the proof-of-work signatures derive from */
    public const FIELD_POW_SECRET = "pow_secret";

    /** @var string signature of the one challenge currently open */
    public const FIELD_POW_CHALLENGE = "pow_challenge";

    /** @var string expected CAPTCHA phrase */
    public const FIELD_PHRASE = "phrase";

    /** @var string microtime(true) of the last image generation */
    public const FIELD_LAST_GENERATION = "last_generation";

    /** @var string[] */
    private const ALL_FIELDS = [
        self::FIELD_RENDERED_AT,
        self::FIELD_HONEYPOT,
        self::FIELD_POW_SECRET,
        self::FIELD_POW_CHALLENGE,
        self::FIELD_PHRASE,
        self::FIELD_LAST_GENERATION,
    ];

    /** @var ilAuthGuardSessionStore */
    private ilAuthGuardSessionStore $store;

    /** @var string */
    private string $form_id;

    /**
     * @param ilAuthGuardSessionStore $store
     * @param string $form_id
     * @throws InvalidArgumentException when the form id has the wrong shape
     * @return void
     */
    public function __construct(ilAuthGuardSessionStore $store, string $form_id)
    {
        if (!self::isValidFormId($form_id)) {
            throw new InvalidArgumentException(
                "A form id must match " . self::FORM_ID_PATTERN
            );
        }

        $this->store = $store;
        $this->form_id = $form_id;
    }

    /**
     * @param string $form_id
     * @return bool
     */
    public static function isValidFormId(string $form_id): bool
    {
        return preg_match(self::FORM_ID_PATTERN, $form_id) === 1;
    }

    /**
     * @return string
     */
    public function getFormId(): string
    {
        return $this->form_id;
    }

    /**
     * @param string $field one of the FIELD_ constants
     * @return mixed null when nothing is stored
     */
    public function get(string $field): mixed
    {
        return $this->store->get($this->key($field));
    }

    /**
     * @param string $field one of the FIELD_ constants
     * @param mixed $value
     * @return void
     */
    public function set(string $field, mixed $value): void
    {
        $this->store->set($this->key($field), $value);
    }

    /**
     * @param string $field one of the FIELD_ constants
     * @return void
     */
    public function clear(string $field): void
    {
        $this->store->clear($this->key($field));
    }

    /**
     * Removes every value of this form, which makes a verification single
     * use.
     *
     * @return void
     */
    public function clearAll(): void
    {
        foreach (self::ALL_FIELDS as $field) {
            $this->clear($field);
        }
    }

    /**
     * True once a render has recorded its timestamp.
     *
     * @return bool
     */
    public function isRendered(): bool
    {
        return $this->get(self::FIELD_RENDERED_AT) !== null;
    }

    /**
     * @param string $field
     * @return string
     */
    private function key(string $field): string
    {
        return "authguard." . $this->form_id . "." . $field;
    }
}
