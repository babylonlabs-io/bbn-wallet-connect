import { IBTCProvider, Network, type BTCConfig, type WalletMetadata } from "@/core/types";

import logo from "./logo.svg";
import { KeystoneAccount, KeystoneProvider, WALLET_PROVIDER_NAME } from "./provider";

const metadata: WalletMetadata<IBTCProvider, BTCConfig> = {
  id: "keystone",
  name: WALLET_PROVIDER_NAME,
  icon: logo,
  docs: "https://www.keyst.one/btc-only",
  createProvider: (wallet, config, account) => new KeystoneProvider(wallet, config, account as KeystoneAccount),
  networks: [Network.MAINNET, Network.SIGNET],
  label: "Hardware wallet",
};

export default metadata;
