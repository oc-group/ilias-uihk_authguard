/**
 * AuthGuard: draws the hCaptcha widget into every protected form of the page.
 *
 * The widgets are rendered explicitly, one per form, so several protected forms on one page each get their own
 * widget and their own answer field (h-captcha-response). hCaptcha's script is loaded at most once, and only when
 * a form carries this widget; it is the only script the plugin takes from outside the installation for this
 * provider. The module is imported by every rendered form; the browser runs it once per page, after the whole page
 * is parsed.
 */
const API_URL = "https://js.hcaptcha.com/1/api.js?render=explicit&onload=authguardHcaptchaReady";
const API_MARKER = "data-authguard-hcaptcha-api";

/**
 * Renders the widgets that are not drawn yet.
 *
 * @returns {void}
 */
function renderPending() {
    document.querySelectorAll(".ilAuthGuardHcaptcha[data-authguard-sitekey]:not([data-authguard-rendered])")
        .forEach((element) => {
            element.setAttribute("data-authguard-rendered", "1");
            globalThis.hcaptcha.render(element, { sitekey: element.getAttribute("data-authguard-sitekey") });
        });
}

globalThis.authguardHcaptchaReady = renderPending;

if (globalThis.hcaptcha && typeof globalThis.hcaptcha.render === "function") {
    renderPending();
} else if (!document.querySelector("script[" + API_MARKER + "]")) {
    const script = document.createElement("script");
    script.src = API_URL;
    script.async = true;
    script.defer = true;
    script.setAttribute(API_MARKER, "1");
    document.head.appendChild(script);
}
