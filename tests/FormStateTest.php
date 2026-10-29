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

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

require_once __DIR__ . "/ArraySessionStore.php";

class FormStateTest extends TestCase
{
    /**
     * @return array<string, array{0: string}>
     */
    public static function validFormIds(): array
    {
        return [
            "registration" => ["registration"],
            "with digits and dashes" => ["dclf-12_a"],
            "single char" => ["a"],
            "64 chars" => [str_repeat("a", 64)],
        ];
    }

    /**
     * @return array<string, array{0: string}>
     */
    public static function invalidFormIds(): array
    {
        return [
            "empty" => [""],
            "upper case" => ["Registration"],
            "space" => ["a b"],
            "dot" => ["a.b"],
            "slash" => ["../x"],
            "65 chars" => [str_repeat("a", 65)],
            "newline" => ["abc\n"],
        ];
    }

    #[DataProvider("validFormIds")]
    public function testAcceptsValidFormIds(string $form_id): void
    {
        $this->assertTrue(\ilAuthGuardFormState::isValidFormId($form_id));
        $state = new \ilAuthGuardFormState(new ArraySessionStore(), $form_id);
        $this->assertSame($form_id, $state->getFormId());
    }

    #[DataProvider("invalidFormIds")]
    public function testRejectsInvalidFormIds(string $form_id): void
    {
        $this->assertFalse(\ilAuthGuardFormState::isValidFormId($form_id));
        $this->expectException(\InvalidArgumentException::class);
        new \ilAuthGuardFormState(new ArraySessionStore(), $form_id);
    }

    public function testTwoFormIdsDoNotShareValues(): void
    {
        $store = new ArraySessionStore();
        $a = new \ilAuthGuardFormState($store, "form-a");
        $b = new \ilAuthGuardFormState($store, "form-b");

        $a->set(\ilAuthGuardFormState::FIELD_PHRASE, "abc");
        $b->set(\ilAuthGuardFormState::FIELD_PHRASE, "xyz");

        $this->assertSame("abc", $a->get(\ilAuthGuardFormState::FIELD_PHRASE));
        $this->assertSame("xyz", $b->get(\ilAuthGuardFormState::FIELD_PHRASE));

        $a->clearAll();

        $this->assertNull($a->get(\ilAuthGuardFormState::FIELD_PHRASE));
        $this->assertSame("xyz", $b->get(\ilAuthGuardFormState::FIELD_PHRASE));
    }

    public function testEveryKeyCarriesTheFormIdPrefix(): void
    {
        $store = new ArraySessionStore();
        $state = new \ilAuthGuardFormState($store, "my-form");
        $state->set(\ilAuthGuardFormState::FIELD_RENDERED_AT, 1.5);
        $state->set(\ilAuthGuardFormState::FIELD_HONEYPOT, "x");

        foreach (array_keys($store->data) as $key) {
            $this->assertStringStartsWith("authguard.my-form.", $key);
        }
    }

    public function testIsRenderedFollowsTheRenderTimestamp(): void
    {
        $state = new \ilAuthGuardFormState(new ArraySessionStore(), "f");
        $this->assertFalse($state->isRendered());

        $state->set(\ilAuthGuardFormState::FIELD_RENDERED_AT, 0.0);
        $this->assertTrue($state->isRendered());
    }

    public function testClearAllRemovesEveryField(): void
    {
        $store = new ArraySessionStore();
        $state = new \ilAuthGuardFormState($store, "f");
        foreach (
            [
                \ilAuthGuardFormState::FIELD_RENDERED_AT,
                \ilAuthGuardFormState::FIELD_HONEYPOT,
                \ilAuthGuardFormState::FIELD_POW_SECRET,
                \ilAuthGuardFormState::FIELD_POW_CHALLENGE,
                \ilAuthGuardFormState::FIELD_PHRASE,
                \ilAuthGuardFormState::FIELD_LAST_GENERATION,
            ] as $field
        ) {
            $state->set($field, "v");
        }

        $state->clearAll();

        $this->assertSame([], $store->data);
    }
}
