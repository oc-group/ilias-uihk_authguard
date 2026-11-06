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

    /** @var string form field a validation error belongs to */
    public const FIELD_PROVIDER = "provider";

    /** @var string form field of the unreachable-vendor choice */
    public const FIELD_ACCEPT_WHEN_UNREACHABLE = "accept_when_unreachable";

    /** @var string id of the selected provider */
    private const KEY_PROVIDER = "provider";

    /** @var string "1" when a submit is accepted while the vendor cannot be reached */
    private const KEY_ACCEPT_WHEN_UNREACHABLE = "accept_when_unreachable";

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
     * The stored choice, whatever the state of its settings.
     *
     * @return string the id of a provider of the registry, Altcha when the
     *                stored value names none
     */
    public function getProvider(): string
    {
        $stored = $this->getString(self::KEY_PROVIDER, ilAuthGuardProviderRegistry::DEFAULT_ID);

        return ilAuthGuardProviderRegistry::isKnownId($stored) ? $stored : ilAuthGuardProviderRegistry::DEFAULT_ID;
    }

    /**
     * @param string $provider the id of a provider of the registry
     * @throws InvalidArgumentException when the value is none
     * @return void
     */
    public function setProvider(string $provider): void
    {
        if (!ilAuthGuardProviderRegistry::isKnownId($provider)) {
            throw new InvalidArgumentException("Unknown challenge provider.");
        }

        $this->setString(self::KEY_PROVIDER, $provider);
    }

    /**
     * Whether a submit is accepted when an external provider's vendor
     * cannot be reached. Off unless stored: the safe default is to reject.
     *
     * @return bool
     */
    public function isAcceptWhenUnreachable(): bool
    {
        return $this->getString(self::KEY_ACCEPT_WHEN_UNREACHABLE, "0") === "1";
    }

    /**
     * @param bool $accept
     * @return void
     */
    public function setAcceptWhenUnreachable(bool $accept): void
    {
        $this->setString(self::KEY_ACCEPT_WHEN_UNREACHABLE, $accept ? "1" : "0");
    }

    /**
     * The provider the checks actually use: the selected one only when its
     * settings are complete, Altcha otherwise.
     *
     * @return string the id of a provider of the registry
     */
    public function getEffectiveProvider(): string
    {
        return ilAuthGuardProviderRegistry::createDefault()->resolve($this)->getId();
    }

    /**
     * A setting of a provider, plaintext.
     *
     * @param string $provider provider id
     * @param string $field field name, see ilAuthGuardProviderField
     * @param string $default
     * @return string
     */
    public function getProviderValue(string $provider, string $field, string $default = ""): string
    {
        return $this->getString($this->providerKey($provider, $field), $default);
    }

    /**
     * @param string $provider provider id
     * @param string $field field name
     * @param string $value
     * @return void
     */
    public function setProviderValue(string $provider, string $field, string $value): void
    {
        $this->setString($this->providerKey($provider, $field), $value);
    }

    /**
     * Whether a secret is stored, without decrypting it.
     *
     * @param string $provider provider id
     * @param string $field field name
     * @return bool
     */
    public function hasProviderSecret(string $provider, string $field): bool
    {
        return $this->getString($this->providerKey($provider, $field), "") !== "";
    }

    /**
     * @param string $provider provider id
     * @param string $field field name
     * @throws RuntimeException when the stored value cannot be decrypted
     * @return string empty when none is stored
     */
    public function getProviderSecret(string $provider, string $field): string
    {
        return $this->decrypt($this->getString($this->providerKey($provider, $field), ""));
    }

    /**
     * Encrypts and stores a secret; an empty value is ignored, so a form
     * left empty keeps the stored secret.
     *
     * @param string $provider provider id
     * @param string $field field name
     * @param string $secret
     * @throws RuntimeException when the value cannot be encrypted
     * @return void
     */
    public function setProviderSecret(string $provider, string $field, string $secret): void
    {
        if ($secret === "") {
            return;
        }

        $this->setString($this->providerKey($provider, $field), $this->encrypt($secret));
    }

    /**
     * The storage key of a provider's setting. For reCAPTCHA v2 this is
     * "recaptcha_site_key" and "recaptcha_secret_key", the keys of the
     * versions before providers were pluggable.
     *
     * @param string $provider
     * @param string $field
     * @return string
     */
    private function providerKey(string $provider, string $field): string
    {
        return $provider . "_" . $field;
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
