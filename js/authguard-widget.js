/**
 * AuthGuard: loads the Altcha widget and serialises its requests.
 *
 * ILIAS keeps the session in the database without locking: every request loads the whole session and writes it
 * back. Each form's challenge is stored in that session, so two widgets that fetch their challenge at the same
 * moment (two protected forms on one page, onload) overwrite each other and the earlier challenge is lost.
 * Every widget therefore sends its requests through one queue: the next request starts after the previous one
 * has been answered completely.
 *
 * Wired in through the supported global defaults of Altcha ($altcha.defaults), not by patching the package.
 * The module is imported by every rendered form; the browser runs it once per page.
 */
import "../node_modules/altcha/dist/main/altcha.i18n.min.js";

let tail = Promise.resolve();

/**
 * @param {RequestInfo | URL} input
 * @param {RequestInit} [init]
 * @returns {Promise<Response>}
 */
function queuedFetch(input, init) {
    const run = tail.then(async () => {
        const response = await fetch(input, init);
        // read the body here so the request is finished, not just started, before the next one begins
        const body = await response.arrayBuffer();

        return new Response(body, {
            status: response.status,
            statusText: response.statusText,
            headers: response.headers,
        });
    });
    tail = run.then(() => undefined, () => undefined);

    return run;
}

globalThis.$altcha.defaults.set({ fetch: queuedFetch });
