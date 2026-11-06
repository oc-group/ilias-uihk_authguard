/**
 * AuthGuard: draws the Friendly Captcha widget into every protected form of the page.
 *
 * The widget is the unmodified Friendly Captcha SDK (npm package @friendlycaptcha/sdk, MPL-2.0), served from this
 * plugin like the Altcha widget, not from a CDN. It still fetches the puzzle from Friendly Captcha, at the global
 * or the EU endpoint the form names. One widget is created per form, so several protected forms on one page each
 * get their own widget and their own answer field (frc-captcha-response). The puzzle starts at once, so it is
 * solved by the time the visitor submits. The module is imported by every rendered form; the browser runs it once
 * per page, after the whole page is parsed.
 */
import { FriendlyCaptchaSDK } from "../node_modules/@friendlycaptcha/sdk/sdk.js";

const sdk = new FriendlyCaptchaSDK();

document.querySelectorAll(".ilAuthGuardFriendlyCaptcha[data-authguard-sitekey]:not([data-authguard-rendered])")
    .forEach((element) => {
        element.setAttribute("data-authguard-rendered", "1");
        sdk.createWidget({
            element,
            sitekey: element.getAttribute("data-authguard-sitekey"),
            apiEndpoint: element.getAttribute("data-authguard-endpoint") === "eu" ? "eu" : "global",
            startMode: "auto",
        });
    });
