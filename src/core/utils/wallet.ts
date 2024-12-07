import { Network } from "@/core/types";

export function validateNetwork(network: Network): void {
  if (![Network.MAINNET, Network.SIGNET, Network.TESTNET].includes(network)) {
    throw new Error(`Unsupported network: ${network}. Please provide a valid network.`);
  }
}
