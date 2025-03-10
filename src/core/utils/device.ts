export const isMobileDevice = (): boolean => {
  if (typeof window === "undefined") return false;

  const userAgent = window.navigator.userAgent;
  const mobileRegex = /Android|webOS|iPhone|iPad|iPod|BlackBerry|IEMobile|Opera Mini/i;
  const isMobileBrowser = mobileRegex.test(userAgent);
  const hasAppSpecificIdentifiers = /OKX|Binance|Trust\/|TokenPocket|imToken/i.test(userAgent);
  const isMobileSize = window.innerWidth <= 768;

  return isMobileBrowser || hasAppSpecificIdentifiers || isMobileSize;
};

export const hasInjectableWallets = (): boolean => {
  if (typeof window === "undefined") return false;

  const hasBtcWallet = typeof (window as any).btcwallet !== "undefined";
  const hasBbnWallet = typeof (window as any).bbnwallet !== "undefined";

  return hasBtcWallet || hasBbnWallet;
};

export const isBrowserExtension = (): boolean => {
  if (typeof window === "undefined") return false;

  const isStandardBrowser = /Chrome|Firefox|Safari|Edge/i.test(window.navigator.userAgent);

  const isNotWebView =
    !/Android|iPhone|iPad|iPod/i.test(window.navigator.userAgent) || !/wv|WebView/i.test(window.navigator.userAgent);

  return isStandardBrowser && isNotWebView;
};

export const isDesktopWalletApp = (): boolean => {
  if (typeof window === "undefined") return false;

  if (isMobileDevice() || isBrowserExtension()) {
    return false;
  }

  if (hasInjectableWallets()) {
    return true;
  }

  const userAgent = window.navigator.userAgent;
  return userAgent.includes("Wallet") || userAgent.includes("wallet");
};

export const shouldShowInjectableWallets = (): boolean => {
  // Always show injectable wallets on mobile
  const isMobile = isMobileDevice();
  if (isMobile) {
    return true;
  }

  // On desktop, only show injectable wallets if inside a desktop wallet app
  return isDesktopWalletApp();
};
