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
 * What is specific to one external provider in its draft privacy text and in
 * the list of what to check before using it. The common structure and the
 * common checks live in templates/default/tpl.privacy_draft.html, filled in
 * by ilAuthGuardPrivacyText. Every value is English plain text.
 */
final class ilAuthGuardPrivacyFacts
{
    /**
     * @param string $name provider name in the heading of the draft
     * @param string $service the service as the sentence "This website uses
     *                        ..." names it
     * @param string $purpose what the service does for the forms, finishing
     *                        the sentence "... on its forms to ..."
     * @param string $about the rest of the first paragraph: the vendor
     * @param string $processing the whole second paragraph: what the vendor
     *                           receives and does with it
     * @param string $controller the roles, the contract and the location,
     *                           after "Data controller: [...]."
     * @param string $consent_subject what the ePrivacy consent question is
     *                                about, after "the ePrivacy rules for"
     * @param string $more_information links or the placeholder for them
     * @param string[] $checks the checks only this provider needs, between
     *                         the controller check and the common ones
     * @return void
     */
    public function __construct(
        public readonly string $name,
        public readonly string $service,
        public readonly string $purpose,
        public readonly string $about,
        public readonly string $processing,
        public readonly string $controller,
        public readonly string $consent_subject,
        public readonly string $more_information,
        public readonly array $checks = []
    ) {
    }
}
