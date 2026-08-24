import { chromium } from "playwright";

const browser = await chromium.launch();
const page = await browser.newPage();
const errors = [];
page.on("pageerror", (e) => errors.push(`pageerror: ${e.message}`));
page.on("console", (m) => errors.push(`console.${m.type()}: ${m.text()}`));
page.on("requestfailed", (r) => errors.push(`reqfail: ${r.url()} ${r.failure()?.errorText}`));

await page.goto("http://localhost:8080/", { waitUntil: "networkidle" });
await page.waitForTimeout(1500);
for (const e of errors) console.log(e);
await browser.close();
