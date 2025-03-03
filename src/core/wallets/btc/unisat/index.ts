import { IBTCProvider, Network, type BTCConfig, type WalletMetadata } from "@/core/types";

import logo from "./logo.svg";
import { UnisatProvider, WALLET_PROVIDER_NAME } from "./provider";

const metadata: WalletMetadata<IBTCProvider, BTCConfig> = {
  id: "unisat",
  name: WALLET_PROVIDER_NAME,
  icon: logo,
  docs: "https://unisat.io/download",
  wallet: "unisat",
  createProvider: (wallet, config, account) => new UnisatProvider(wallet, config, account),
  networks: [Network.MAINNET, Network.SIGNET],
};

export default metadata;
