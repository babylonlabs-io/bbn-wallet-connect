import { IBBNProvider, Network, type BBNConfig, type WalletMetadata } from "@/core/types";

import logo from "./logo.svg";
import { LeapProvider, WALLET_PROVIDER_NAME } from "./provider";

const metadata: WalletMetadata<IBBNProvider, BBNConfig> = {
  id: "leap",
  name: WALLET_PROVIDER_NAME,
  icon: logo,
  docs: "https://www.leapwallet.io/",
  wallet: "leap",
  createProvider: (wallet, config, account) => new LeapProvider(wallet, config, account),
  networks: [Network.MAINNET, Network.SIGNET],
};

export default metadata;
