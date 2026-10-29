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

use ILIAS\Filesystem\Stream\Streams;
use ILIAS\HTTP\Response\ResponseHeader;
use ILIAS\HTTP\StatusCode;

/**
 * Shared plugin utility: the CAPTCHA comparison and the HTTP responses
 * reused across the plugin's other classes.
 */
class ilAuthGuardHelper
{
    /** @var int RFC 6585 status code, not covered by core's StatusCode */
    private const HTTP_TOO_MANY_REQUESTS = 429;

    /**
     * Compares the submitted answer against the expected phrase.
     * Case-insensitive and whitespace-trimmed by design: the rendered phrase
     * is distorted enough that a legitimate user routinely misjudges letter
     * case, and a CAPTCHA is a bot deterrent, not a precision text match.
     *
     * @param string $submitted the value read from the captcha_code POST field
     * @param string $expected the value read from the session
     * @return bool
     */
    public static function isValid(string $submitted, string $expected): bool
    {
        $expected = strtolower(trim($expected));
        if ($expected === "") {
            // Nothing to compare against; never treat that as a pass.
            return false;
        }

        return hash_equals($expected, strtolower(trim($submitted)));
    }

    /**
     * Sends a plain 404 and terminates the request.
     *
     * @return never
     */
    public static function respondNotFound(): never
    {
        global $DIC;

        /** @var \ILIAS\HTTP\Services $http */
        $http = $DIC->http();

        $http->saveResponse($http->response()->withStatus(StatusCode::HTTP_NOT_FOUND));
        $http->sendResponse();
        $http->close();
    }

    /**
     * Sends a 429 with a Retry-After header and terminates the request,
     * without regenerating the image or touching the stored phrase.
     *
     * @param int $retry_after_seconds
     * @return never
     */
    public static function respondTooManyRequests(int $retry_after_seconds): never
    {
        global $DIC;

        /** @var \ILIAS\HTTP\Services $http */
        $http = $DIC->http();

        $http->saveResponse(
            $http->response()
                ->withStatus(self::HTTP_TOO_MANY_REQUESTS)
                ->withHeader(ResponseHeader::RETRY_AFTER, (string) $retry_after_seconds)
        );
        $http->sendResponse();
        $http->close();
    }

    /**
     * Sends a body with caching suppressed and terminates the request. Not
     * routed through $DIC->fileDelivery(), whose caching cannot be disabled
     * on every supported version, while a cached puzzle or challenge would
     * keep serving a value the session has already replaced. Headers as
     * core's BaseDelivery emits them with its caching off.
     *
     * @param string $body the raw bytes
     * @param string $mime_type the media type, e.g. "image/jpeg"
     * @param string|null $disposition the Content-Disposition value, if any
     * @return never
     */
    public static function respondUncacheable(
        string $body,
        string $mime_type,
        ?string $disposition
    ): never {
        global $DIC;

        /** @var \ILIAS\HTTP\Services $http */
        $http = $DIC->http();

        $response = $http->response()
            ->withHeader(ResponseHeader::CONTENT_TYPE, $mime_type)
            ->withHeader(ResponseHeader::CONTENT_LENGTH, (string) strlen($body))
            ->withHeader(
                ResponseHeader::CACHE_CONTROL,
                "no-store, no-cache, must-revalidate, post-check=0, pre-check=0"
            )
            ->withHeader(ResponseHeader::EXPIRES, "0")
            ->withBody(Streams::ofString($body));

        if ($disposition !== null) {
            $response = $response->withHeader(ResponseHeader::CONTENT_DISPOSITION, $disposition);
        }

        $http->saveResponse($response);
        $http->sendResponse();
        $http->close();
    }

    /**
     * Stores $message as a session-backed failure message and redirects to the
     * registration form's GET entry point, so it re-renders with the standard
     * page banner. The on-screen-message API is not available this early in the
     * request, and redirecting through the usual routing call would re-enter
     * the plugin's own construction and recurse.
     *
     * @param string $message
     * @return never
     */
    public static function redirectWithFailureMessage(string $message): never
    {
        global $DIC;

        ilSession::set(ilGlobalTemplateInterface::MESSAGE_TYPE_FAILURE, $message);

        $target_url = (defined("ILIAS_HTTP_PATH") ? ILIAS_HTTP_PATH . "/" : "") . "register.php";

        session_write_close();

        /** @var \ILIAS\HTTP\Services $http */
        $http = $DIC->http();

        $http->saveResponse(
            $http->response()
                ->withStatus(StatusCode::HTTP_FOUND)
                ->withHeader(ResponseHeader::LOCATION, $target_url)
        );
        $http->sendResponse();
        $http->close();
    }
}
