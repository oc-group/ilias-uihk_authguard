/**
 * AuthGuard: fetches the Google reCAPTCHA v3 token of every protected form of the page.
 *
 * reCAPTCHA v3 has no widget: the page asks Google for a token that stands for an action and the server asks
 * Google how likely a human made it. A token is valid for two minutes, so it is fetched when the page is ready
 * and renewed every 90 seconds, which keeps a form that stays open for a while submittable. Each form has a
 * hidden field that receives the token and names its own action. Google's script is loaded at most once, and only
 * when a form carries this field. The module is imported by every rendered form; the browser runs it once per
 * page, after the whole page is parsed.
 */
const API_URL = "https://www.google.com/recaptcha/api.js?render=";
const API_MARKER = "data-authguard-recaptcha3-api";
const RENEW_MILLISECONDS = 90000;
const SELECTOR = "input.ilAuthGuardRecaptcha3[data-authguard-sitekey][data-authguard-action]";

/**
 * Asks Google for a fresh token for every field of the page.
 *
 * @returns {void}
 */
function fetchTokens() {
    document.querySelectorAll(SELECTOR).forEach((field) => {
        globalThis.grecaptcha
            .execute(field.getAttribute("data-authguard-sitekey"), { action: field.getAttribute("data-authguard-action") })
            .then((token) => {
                field.value = token;
            })
            .catch(() => {
                field.value = "";
            });
    });
}

/**
 * @returns {void}
 */
function start() {
    globalThis.grecaptcha.ready(() => {
        fetchTokens();
        globalThis.setInterval(fetchTokens, RENEW_MILLISECONDS);
    });
}

const first = document.querySelector(SELECTOR);

if (first !== null) {
    if (globalThis.grecaptcha && typeof globalThis.grecaptcha.ready === "function") {
        start();
    } else if (!document.querySelector("script[" + API_MARKER + "]")) {
        const script = document.createElement("script");
        script.src = API_URL + encodeURIComponent(first.getAttribute("data-authguard-sitekey"));
        script.async = true;
        script.defer = true;
        script.addEventListener("load", start);
        script.setAttribute(API_MARKER, "1");
        document.head.appendChild(script);
    }
}
