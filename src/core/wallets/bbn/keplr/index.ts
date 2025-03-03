import { IBBNProvider, Network, type BBNConfig, type WalletMetadata } from "@/core/types";

import logo from "./logo.svg";
import { KeplrProvider, WALLET_PROVIDER_NAME } from "./provider";

const metadata: WalletMetadata<IBBNProvider, BBNConfig> = {
  id: "keplr",
  name: WALLET_PROVIDER_NAME,
  icon: logo,
  docs: "https://www.keplr.app/",
  wallet: "keplr",
  createProvider: (wallet, config, account) => new KeplrProvider(wallet, config, account),
  networks: [Network.MAINNET, Network.SIGNET],
};

export default metadata;
