import { useCallback, useEffect } from "react";

import { useChainProviders } from "@/context/Chain.context";
import { useInscriptionProvider } from "@/context/Inscriptions.context";
import { accountStorage } from "@/core/storage";
import { IChain, IWallet } from "@/core/types";
import { validateAddressWithPK } from "@/core/utils/wallet";

import { useWidgetState } from "./useWidgetState";

interface Props {
  onError?: (e: Error) => void;
}

export function useWalletConnectors({ onError }: Props) {
  const connectors = useChainProviders();
  const { selectWallet, removeWallet, displayLoader, displayChains, displayInscriptions, displayError, confirm } =
    useWidgetState();
  const { showAgain } = useInscriptionProvider();

  // Connecting event
  useEffect(() => {
    const connectorArr = Object.values(connectors);

    const unsubscribeArr = connectorArr.filter(Boolean).map((connector) =>
      connector.on("connecting", (message: string) => {
        displayLoader?.(message);
      }),
    );

    return () => unsubscribeArr.forEach((unsubscribe) => unsubscribe());
  }, [displayLoader, connectors]);

  // Connect Event
  useEffect(() => {
    const connectorArr = Object.values(connectors).filter(Boolean);

    const handlers: Record<string, (connector: any) => (connectedWallet: IWallet) => void> = {
      BTC: (connector) => (connectedWallet) => {
        if (connectedWallet && connectedWallet.account) {
          selectWallet?.("BTC", connectedWallet);
          accountStorage.set(connector.id, { walletId: connectedWallet.id, account: connectedWallet.account });
        }

        const goToNextScreen = () => void (showAgain ? displayInscriptions?.() : displayChains?.());

        if (
          validateAddressWithPK(
            connectedWallet.account?.address ?? "",
            connectedWallet.account?.publicKeyHex ?? "",
            connector.config.network,
          )
        ) {
          goToNextScreen();
        } else {
          displayError?.({
            title: "Public Key Mismatch",
            description:
              "The Bitcoin address and Public Key for this wallet do not match. Please contact your wallet provider for support.",
            onSubmit: goToNextScreen,
            onCancel: () => {
              removeWallet?.(connector.id);
              displayChains?.();
            },
          });
        }
      },
      BBN: (connector) => (connectedWallet) => {
        if (connectedWallet && connectedWallet.account) {
          selectWallet?.(connector.id, connectedWallet);
          accountStorage.set(connector.id, { walletId: connectedWallet.id, account: connectedWallet.account });
        }

        displayChains?.();
      },
    };

    const unsubscribeArr = connectorArr.map((connector) =>
      connector.on("connect", handlers[connector.id]?.(connector)),
    );

    if (connectorArr.length && connectorArr.every((connector) => connector.connectedWallet)) {
      connectorArr.forEach((connector) => {
        selectWallet?.(connector.id, connector.connectedWallet);
      });
      confirm?.();
      displayChains?.();
    }

    return () => unsubscribeArr.forEach((unsubscribe) => unsubscribe());
  }, [selectWallet, removeWallet, displayInscriptions, displayChains, confirm, connectors, showAgain]);

  // Disconnect Event
  useEffect(() => {
    const connectorArr = Object.values(connectors);

    const unsubscribeArr = connectorArr.filter(Boolean).map((connector) =>
      connector.on("disconnect", (connectedWallet: IWallet) => {
        if (connectedWallet) {
          removeWallet?.(connector.id);
          displayChains?.();
          accountStorage.delete(connector.id);
        }
      }),
    );

    return () => unsubscribeArr.forEach((unsubscribe) => unsubscribe());
  }, [removeWallet, displayChains, connectors]);

  // Error Event
  useEffect(() => {
    const connectorArr = Object.values(connectors);

    const unsubscribeArr = connectorArr.filter(Boolean).map((connector) =>
      connector.on("error", (error: Error) => {
        onError?.(error);
        displayChains?.();
      }),
    );

    return () => unsubscribeArr.forEach((unsubscribe) => unsubscribe());
  }, [onError, displayChains, connectors]);

  const connect = useCallback(
    async (chain: IChain, wallet: IWallet) => {
      const connector = connectors[chain.id as keyof typeof connectors];
      await connector?.connect(wallet.id);
    },
    [connectors],
  );

  const disconnect = useCallback(
    async (chainId: string) => {
      const connector = connectors[chainId as keyof typeof connectors];
      await connector?.disconnect();
    },
    [connectors],
  );

  return { connect, disconnect };
}
