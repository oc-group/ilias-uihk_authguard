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

use ILIAS\Filesystem\Filesystem;

/**
 * Typed accessors over the plugin's settings, held in the core "settings"
 * table under the module named by self::MODULE. Constructed without
 * arguments: several callers run under a partial bootstrap, and ilSetting
 * keeps one row set per module per request.
 */
final class ilAuthGuardSettings
{
    /** @var string ilSetting module every key below is stored under */
    public const MODULE = "plugin_" . ilAuthGuardPlugin::PLUGIN_ID;

    /** @var string proof-of-work, no external service */
    public const PROVIDER_ALTCHA = "altcha";

    /** @var string Google reCAPTCHA v2 checkbox */
    public const PROVIDER_RECAPTCHA = "recaptcha";

    /** @var string shape of a Google site key and of a Google secret key */
    public const GOOGLE_KEY_PATTERN = "/^[A-Za-z0-9_-]{20,100}$/D";

    /** @var string form field a validation error belongs to */
    public const FIELD_PROVIDER = "provider";

    /** @var string form field a validation error belongs to */
    public const FIELD_SITE_KEY = "recaptcha_site_key";

    /** @var string form field a validation error belongs to */
    public const FIELD_SECRET_KEY = "recaptcha_secret_key";

    /** @var string "altcha" or "recaptcha" */
    private const KEY_PROVIDER = "provider";

    /** @var string public key of the reCAPTCHA site, plaintext */
    private const KEY_RECAPTCHA_SITE_KEY = "recaptcha_site_key";

    /** @var string private key of the reCAPTCHA site, "v1:" encrypted */
    private const KEY_RECAPTCHA_SECRET_KEY = "recaptcha_secret_key";

    /** @var string stored-format prefix of an encrypted value */
    private const PREFIX = "v1:";

    /** @var string */
    private const CIPHER = "aes-256-gcm";

    /** @var int */
    private const IV_LENGTH = 12;

    /** @var int */
    private const TAG_LENGTH = 16;

    /** @var string path of the encryption key in the storage filesystem */
    private const KEY_FILE = ilAuthGuardPlugin::PLUGIN_ID . "/encryption.sec";

    /** @var ilSetting */
    private ilSetting $store;

    /** @var Filesystem|null replaces the storage filesystem (tests) */
    private ?Filesystem $storage;

    /**
     * @param ilSetting|null $store replaces the module's store (tests)
     * @param Filesystem|null $storage replaces the storage filesystem (tests)
     * @return void
     */
    public function __construct(?ilSetting $store = null, ?Filesystem $storage = null)
    {
        $this->store = $store ?? new ilSetting(self::MODULE);
        $this->storage = $storage;
    }

    /**
     * Removes every stored setting. The encryption key file is not removed
     * here: the uninstall hook deletes the plugin's storage directory.
     *
     * @return void
     */
    public function deleteAll(): void
    {
        $this->store->deleteAll();
    }

    /**
     * The stored choice, whatever the state of the keys.
     *
     * @return string one of the PROVIDER_ constants
     */
    public function getProvider(): string
    {
        $stored = $this->getString(self::KEY_PROVIDER, self::PROVIDER_ALTCHA);

        return $stored === self::PROVIDER_RECAPTCHA ? self::PROVIDER_RECAPTCHA : self::PROVIDER_ALTCHA;
    }

    /**
     * @param string $provider one of the PROVIDER_ constants
     * @throws InvalidArgumentException when the value is neither
     * @return void
     */
    public function setProvider(string $provider): void
    {
        if ($provider !== self::PROVIDER_ALTCHA && $provider !== self::PROVIDER_RECAPTCHA) {
            throw new InvalidArgumentException("Unknown challenge provider.");
        }

        $this->setString(self::KEY_PROVIDER, $provider);
    }

    /**
     * The provider the checks actually use: reCAPTCHA only when both of its
     * keys are stored, Altcha otherwise.
     *
     * @return string one of the PROVIDER_ constants
     */
    public function getEffectiveProvider(): string
    {
        if ($this->getProvider() === self::PROVIDER_RECAPTCHA && $this->isRecaptchaConfigured()) {
            return self::PROVIDER_RECAPTCHA;
        }

        return self::PROVIDER_ALTCHA;
    }

    /**
     * @return string
     */
    public function getRecaptchaSiteKey(): string
    {
        return $this->getString(self::KEY_RECAPTCHA_SITE_KEY, "");
    }

    /**
     * @param string $site_key
     * @return void
     */
    public function setRecaptchaSiteKey(string $site_key): void
    {
        $this->setString(self::KEY_RECAPTCHA_SITE_KEY, $site_key);
    }

    /**
     * Whether a secret key is stored, without decrypting it.
     *
     * @return bool
     */
    public function hasRecaptchaSecretKey(): bool
    {
        return $this->getString(self::KEY_RECAPTCHA_SECRET_KEY, "") !== "";
    }

    /**
     * @throws RuntimeException when the stored value cannot be decrypted
     * @return string empty when none is stored
     */
    public function getRecaptchaSecretKey(): string
    {
        return $this->decrypt($this->getString(self::KEY_RECAPTCHA_SECRET_KEY, ""));
    }

    /**
     * Encrypts and stores the secret key; an empty value is ignored, so a
     * form left empty keeps the stored key.
     *
     * @param string $secret_key
     * @throws RuntimeException when the value cannot be encrypted
     * @return void
     */
    public function setRecaptchaSecretKey(string $secret_key): void
    {
        if ($secret_key === "") {
            return;
        }

        $this->setString(self::KEY_RECAPTCHA_SECRET_KEY, $this->encrypt($secret_key));
    }

    /**
     * True when both keys are stored. Looks at the stored values only: no
     * decryption, no key file access.
     *
     * @return bool
     */
    public function isRecaptchaConfigured(): bool
    {
        return $this->getRecaptchaSiteKey() !== "" && $this->hasRecaptchaSecretKey();
    }

    /**
     * Checks what a configuration form submits. Choosing reCAPTCHA needs
     * both keys, each in the shape Google issues; the secret key may be
     * left empty only when one is already stored.
     *
     * @param string $provider the submitted choice
     * @param string $site_key the submitted site key
     * @param string $secret_key the submitted secret key, empty keeps the old
     * @param bool $secret_stored whether a secret key is stored already
     * @return array<string, string> lang key by form field, empty when valid
     */
    public static function validate(
        string $provider,
        string $site_key,
        string $secret_key,
        bool $secret_stored
    ): array {
        $errors = [];

        if ($provider !== self::PROVIDER_ALTCHA && $provider !== self::PROVIDER_RECAPTCHA) {
            return [self::FIELD_PROVIDER => "cfg_err_provider"];
        }

        if ($provider === self::PROVIDER_ALTCHA) {
            return $errors;
        }

        if (preg_match(self::GOOGLE_KEY_PATTERN, $site_key) !== 1) {
            $errors[self::FIELD_SITE_KEY] = "cfg_err_site_key";
        }

        if ($secret_key === "" && !$secret_stored) {
            $errors[self::FIELD_SECRET_KEY] = "cfg_err_secret_key";
        } elseif ($secret_key !== "" && preg_match(self::GOOGLE_KEY_PATTERN, $secret_key) !== 1) {
            $errors[self::FIELD_SECRET_KEY] = "cfg_err_secret_key";
        }

        return $errors;
    }

    /**
     * @param string $key
     * @param string $default
     * @return string
     */
    private function getString(string $key, string $default): string
    {
        return (string) $this->store->get($key, $default);
    }

    /**
     * @param string $key
     * @param string $value
     * @return void
     */
    private function setString(string $key, string $value): void
    {
        $this->store->set($key, $value);
    }

    /**
     * @return Filesystem
     */
    private function getStorage(): Filesystem
    {
        global $DIC;

        if ($this->storage === null) {
            $this->storage = $DIC->filesystem()->storage();
        }

        return $this->storage;
    }

    /**
     * Creates the encryption key once and never replaces it: a new key
     * would leave every stored secret unreadable.
     *
     * @return string raw key
     */
    private function getOrCreateKey(): string
    {
        $storage = $this->getStorage();

        if (!$storage->has(self::KEY_FILE)) {
            $storage->write(self::KEY_FILE, bin2hex(random_bytes(32)));
        }

        return $this->readKey();
    }

    /**
     * @throws RuntimeException when the key file is missing or unreadable
     * @return string raw key
     */
    private function readKey(): string
    {
        $storage = $this->getStorage();

        if (!$storage->has(self::KEY_FILE)) {
            throw new RuntimeException("The encryption key of the stored secret is missing.");
        }

        $key = hex2bin($storage->read(self::KEY_FILE));
        if ($key === false || strlen($key) !== 32) {
            throw new RuntimeException("The encryption key of the stored secret is unreadable.");
        }

        return $key;
    }

    /**
     * @param string $plain
     * @throws RuntimeException when encryption fails
     * @return string
     */
    private function encrypt(string $plain): string
    {
        $key = $this->getOrCreateKey();
        $iv = random_bytes(self::IV_LENGTH);
        $tag = "";

        $cipher = openssl_encrypt($plain, self::CIPHER, $key, OPENSSL_RAW_DATA, $iv, $tag, "", self::TAG_LENGTH);
        if ($cipher === false) {
            throw new RuntimeException("The secret could not be encrypted.");
        }

        return self::PREFIX . base64_encode($iv . $tag . $cipher);
    }

    /**
     * A value without the prefix is read as plaintext and encrypted at the
     * next save.
     *
     * @param string $stored
     * @throws RuntimeException when decryption fails
     * @return string
     */
    private function decrypt(string $stored): string
    {
        if ($stored === "" || !str_starts_with($stored, self::PREFIX)) {
            return $stored;
        }

        $raw = base64_decode(substr($stored, strlen(self::PREFIX)), true);
        if ($raw === false || strlen($raw) <= self::IV_LENGTH + self::TAG_LENGTH) {
            throw new RuntimeException("The stored secret is malformed.");
        }

        $plain = openssl_decrypt(
            substr($raw, self::IV_LENGTH + self::TAG_LENGTH),
            self::CIPHER,
            $this->readKey(),
            OPENSSL_RAW_DATA,
            substr($raw, 0, self::IV_LENGTH),
            substr($raw, self::IV_LENGTH, self::TAG_LENGTH)
        );
        if ($plain === false) {
            throw new RuntimeException("The stored secret could not be decrypted.");
        }

        return $plain;
    }
}
