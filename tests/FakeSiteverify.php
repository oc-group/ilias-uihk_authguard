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
 * Replaces the one network method of a siteverify class: records what would
 * be sent, including the request headers, and answers with a canned reply
 * or a failure.
 */
trait FakeTransport
{
    /** @var string */
    public string $reply = "{\"success\": true}";

    /** @var \Throwable|null */
    public ?\Throwable $failure = null;

    /** @var array<int, array{url: string, fields: array<string, string>, headers: string[]}> */
    public array $calls = [];

    protected function post(string $url, array $fields): string
    {
        $this->calls[] = ["url" => $url, "fields" => $fields, "headers" => $this->getRequestHeaders()];
        if ($this->failure !== null) {
            throw $this->failure;
        }

        return $this->reply;
    }
}

final class FakeRecaptcha extends \ilAuthGuardRecaptcha
{
    use FakeTransport;
}

final class FakeRecaptcha3 extends \ilAuthGuardRecaptcha3
{
    use FakeTransport;
}

final class FakeTurnstile extends \ilAuthGuardTurnstile
{
    use FakeTransport;
}

final class FakeHcaptcha extends \ilAuthGuardHcaptcha
{
    use FakeTransport;
}

final class FakeFriendlyCaptcha extends \ilAuthGuardFriendlyCaptcha
{
    use FakeTransport;
}
