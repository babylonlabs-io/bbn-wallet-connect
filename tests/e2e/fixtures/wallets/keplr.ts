import { BrowserContext } from "@playwright/test";

import { EXTENSION_CHROME_INNER_IDS } from "../../setup/downloadExtensions";
import { findServiceWorkerForExtension } from "../../utils/findServiceWorkerForExtension";

export async function setupKeplrWallet(context: BrowserContext, mnemonic: string, password: string) {
  if (!mnemonic) {
    throw new Error("Missing E2E_WALLET_MNEMONIC in environment variables");
  }
  if (!password) {
    throw new Error("Missing E2E_WALLET_PASSWORD in environment variables");
  }

  const keplrSW = await findServiceWorkerForExtension(context, EXTENSION_CHROME_INNER_IDS.KEPLR);
  const keplrId = keplrSW.url().split("/")[2];
  const page = await context.newPage();
  await page.goto(`chrome-extension://${keplrId}/register.html`);

  await page.getByRole("button", { name: "Import an existing wallet" }).click();
  await page.getByRole("button", { name: "Use recovery phrase or" }).click();
  // Enter mnemonic phrase
  const words = mnemonic.trim().split(" ");
  await page.getByRole("button", { name: "12 words" }).click();
  for (let i = 0; i < words.length; i++) {
    await page.getByText("1.2.3.4.5.6.7.8.9.10.11.12.").locator("input").nth(i).fill(words[i]);
  }
  await page.getByRole("button", { name: "Import", exact: true }).click();
  await page.locator('input[name="name"]').click();
  await page.locator('input[name="name"]').fill("Keplr BBN");
  await page.locator('input[name="password"]').click();
  await page.locator('input[name="password"]').fill(password);
  await page.locator('input[name="confirmPassword"]').click();
  await page.locator('input[name="confirmPassword"]').fill(password);
  await page.getByRole("button", { name: "Next" }).click();
  await page.getByRole("button", { name: "Save" }).click();
  await page.getByRole("button", { name: "Finish" }).click();
}
