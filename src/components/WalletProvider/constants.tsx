import { Text } from "@babylonlabs-io/core-ui";

import { WalletButton } from "@/components/WalletButton";
import { ChainConfigArr } from "@/context/Chain.context";
import { Network } from "@/core/types";

import { BBN_TESTNET_RPC_URL, bbnTestnet } from "./tesnet";

export const ONE_HOUR = 60 * 60 * 1000;

export const config: ChainConfigArr = [
  {
    chain: "BTC",
    connectors: [
      {
        id: "tomo-connect",
        widget: () => (
          <div className="pt-10">
            <Text className="mb-4 text-accent-secondary">More wallets with Tomo Connect</Text>
            <WalletButton logo="/images/wallets/tomo.png" name="Tomo Connect" onClick={() => alert("Hello Tomo!")} />
          </div>
        ),
      },
    ],
    config: {
      coinName: "Signet BTC",
      coinSymbol: "sBTC",
      networkName: "BTC signet",
      mempoolApiUrl: "https://mempool.space/signet",
      network: Network.SIGNET,
    },
  },
  {
    chain: "BBN",
    connectors: [
      {
        id: "tomo-connect",
        widget: () => (
          <div className="pt-10">
            <Text className="mb-4 text-accent-secondary">More wallets with Tomo Connect</Text>
            <WalletButton logo="/images/wallets/tomo.png" name="Tomo Connect" onClick={() => alert("Hello Tomo!")} />
          </div>
        ),
      },
    ],
    config: {
      networkName: bbnTestnet.currencies[0].coinDenom,
      networkFullName: bbnTestnet.chainName,
      coinSymbol: bbnTestnet.currencies[0].coinDenom,
      chainId: bbnTestnet.chainId,
      rpc: BBN_TESTNET_RPC_URL,
      chainData: bbnTestnet,
    },
  },
];
