import { chromium } from "playwright";

const browser = await chromium.launch();
const page = await browser.newPage();
const errors = [];
page.on("pageerror", (e) => errors.push(`pageerror: ${e.message}`));
page.on("console", (m) => { if (m.type() === "error") errors.push(`console: ${m.text()}`); });

await page.goto("http://localhost:8080/", { waitUntil: "networkidle" });

// 1. course tab renders
const lessons = await page.locator(".lesson-item").count();
console.log("lesson items:", lessons);

// 2. switch to WinDbg tab, run commands
await page.click('button[data-tab="windbg"]');
await page.fill("#kd-in", "!process 0 0");
await page.press("#kd-in", "Enter");
await page.waitForTimeout(500);
const out1 = await page.locator("#kd-out").innerText();
console.log("process list has lsass:", out1.includes("lsass.exe"));
console.log("process list has kftarget:", out1.includes("kftarget.exe"));

// 3. dt command
await page.fill("#kd-in", "dt nt!_EPROCESS");
await page.press("#kd-in", "Enter");
await page.waitForTimeout(300);
const out2 = await page.locator("#kd-out").innerText();
console.log("dt shows 22h2 offset 0x448:", out2.includes("+0x448"));

// 4. IDE tab: compile + load driver through the full pipeline
await page.click('button[data-tab="ide"]');
await page.click("#btn-compile");
await page.waitForTimeout(4000);
const status = await page.locator("#compile-status").innerText();
console.log("compile+load status:", status);

console.log(errors.length ? `ERRORS:\n${errors.join("\n")}` : "no page errors");
await browser.close();
