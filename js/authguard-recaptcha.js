/**
 * AuthGuard: draws the Google reCAPTCHA v2 checkbox into every protected form of the page.
 *
 * The widgets are rendered explicitly, one per form, so several protected forms on one page each get their own
 * checkbox and their own answer field. Google's script is loaded at most once, and only when a form carries
 * this widget; it is the only script the plugin takes from outside the installation. The module is imported by
 * every rendered form; the browser runs it once per page, after the whole page is parsed.
 */
const API_URL = "https://www.google.com/recaptcha/api.js?render=explicit&onload=authguardRecaptchaReady";
const API_MARKER = "data-authguard-recaptcha-api";

/**
 * Renders the widgets that are not drawn yet.
 *
 * @returns {void}
 */
function renderPending() {
    document.querySelectorAll(".ilAuthGuardRecaptcha[data-authguard-sitekey]:not([data-authguard-rendered])")
        .forEach((element) => {
            element.setAttribute("data-authguard-rendered", "1");
            globalThis.grecaptcha.render(element, { sitekey: element.getAttribute("data-authguard-sitekey") });
        });
}

globalThis.authguardRecaptchaReady = renderPending;

if (globalThis.grecaptcha && typeof globalThis.grecaptcha.ready === "function") {
    globalThis.grecaptcha.ready(renderPending);
} else if (!document.querySelector("script[" + API_MARKER + "]")) {
    const script = document.createElement("script");
    script.src = API_URL;
    script.async = true;
    script.defer = true;
    script.setAttribute(API_MARKER, "1");
    document.head.appendChild(script);
}
