import { BrowserContext } from "@playwright/test";

import { EXTENSION_CHROME_INNER_IDS } from "../../setup/downloadExtensions";
import { findServiceWorkerForExtension } from "../../utils/findServiceWorkerForExtension";

export async function setupOKXWallet(context: BrowserContext, mnemonic: string, password: string) {
  if (!mnemonic) {
    throw new Error("Missing E2E_WALLET_MNEMONIC in environment variables");
  }
  if (!password) {
    throw new Error("Missing E2E_WALLET_PASSWORD in environment variables");
  }

  const okxSW = await findServiceWorkerForExtension(context, EXTENSION_CHROME_INNER_IDS.OKX);
  const okxId = okxSW.url().split("/")[2];
  const extensionPage = await context.newPage();
  await extensionPage.goto(`chrome-extension://${okxId}/popup.html`);

  // Start importing wallet
  await extensionPage.getByText("Import Wallet").click();
  await extensionPage.getByText("Seed phrase or private key").click();

  // Enter mnemonic phrase
  const words = mnemonic.trim().split(" ");
  // Wait for the mnemonic input container to be visible
  await extensionPage.waitForSelector(".mnemonic-words-inputs__container");
  // Fill in each word using the mnemonic-words-inputs__container__input class
  for (let i = 0; i < words.length; i++) {
    await extensionPage.locator(".mnemonic-words-inputs__container__input").nth(i).fill(words[i]);
  }
  await extensionPage.getByTestId("okd-button").click();
  await extensionPage.getByText("Password", { exact: true }).click();
  await extensionPage.getByTestId("okd-button").click();
  await extensionPage.getByPlaceholder("Enter at least 8 characters").click();
  await extensionPage.getByPlaceholder("Enter at least 8 characters").fill(password);
  await extensionPage.getByPlaceholder("Re-enter new password").click();
  await extensionPage.getByPlaceholder("Re-enter new password").fill(password);
  await extensionPage.getByTestId("okd-button").click();
  await extensionPage.getByLabel("Set OKX Wallet as the default").uncheck();
  await extensionPage.getByTestId("okd-button").click();

  // Manage crypto
  await extensionPage.getByTestId("okd-button").click();
  await extensionPage.getByTestId("okd-input").click();
  await extensionPage.getByTestId("okd-input").fill("sBTC");
  await extensionPage
    .locator("div")
    .filter({ hasText: /^sBTCBTC Signet$/ })
    .first()
    .locator(".icon")
    .click();
  // Go back
  await extensionPage.locator(".icon").first().click();
  // Manage address
  await extensionPage
    .locator("div")
    .filter({ hasText: /^sBTC$/ })
    .first()
    .click();
  await extensionPage.getByTestId("okd-popup").getByText("Set default address").click();
  await extensionPage.getByText("Taproot").click();
  // Go back
  await extensionPage.locator("i").first().click();
  await extensionPage.close();
}
