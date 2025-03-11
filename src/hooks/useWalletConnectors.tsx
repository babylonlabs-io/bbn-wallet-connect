import { useCallback, useEffect } from "react";

import { useChainProviders } from "@/context/Chain.context";
import { useInscriptionProvider } from "@/context/Inscriptions.context";
import { useLifeCycleHooks } from "@/context/LifecycleHooks.context";
import { HashMap, IChain, IWallet } from "@/core/types";
import { validateAddressWithPK } from "@/core/utils/wallet";

import { useWidgetState } from "./useWidgetState";

interface Props {
  persistent: boolean;
  accountStorage: HashMap;
  onError?: (e: Error) => void;
}

const ANIMATION_DELAY = 1000;

export function useWalletConnectors({ persistent, accountStorage, onError }: Props) {
  const connectors = useChainProviders();
  const {
    selectWallet,
    removeWallet,
    displayLoader,
    displayChains,
    displayInscriptions,
    displayError,
    confirm,
    close,
    reset,
  } = useWidgetState();
  const { showAgain } = useInscriptionProvider();
  const { verifyBTCAddress, acceptTermsOfService } = useLifeCycleHooks();

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
      BTC: (connector) => async (connectedWallet) => {
        try {
          if (connectedWallet && connectedWallet.account) {
            selectWallet?.("BTC", connectedWallet);
            if (persistent) {
              accountStorage.set(connector.id, connectedWallet.id);
            }
            await acceptTermsOfService?.({
              address: connectedWallet.account.address,
              public_key: connectedWallet.account.publicKeyHex,
            });
          }

          const goToNextScreen = () => void (showAgain ? displayInscriptions?.() : displayChains?.());

          if (
            !validateAddressWithPK(
              connectedWallet.account?.address ?? "",
              connectedWallet.account?.publicKeyHex ?? "",
              connector.config.network,
            )
          ) {
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

            return;
          }

          if (verifyBTCAddress && !(await verifyBTCAddress(connectedWallet.account?.address ?? ""))) {
            for (const connector of connectorArr) {
              await connector.disconnect();
            }

            displayError?.({
              title: "Connection Failed",
              description: "The wallet cannot be connected.",
              submitButton: "",
              cancelButton: "Done",
              onCancel: async () => {
                close?.();
                setTimeout(() => void reset?.(), ANIMATION_DELAY);
              },
            });

            return;
          }

          goToNextScreen();
        } catch (e: any) {
          onError?.(e);
        }
      },
      BBN: (connector) => (connectedWallet) => {
        if (connectedWallet) {
          selectWallet?.(connector.id, connectedWallet);

          if (persistent) {
            accountStorage.set(connector.id, connectedWallet.id);
          }
        }

        displayChains?.();
      },
    };

    const unsubscribeArr = connectorArr.map((connector) =>
      connector.on("connect", handlers[connector.id]?.(connector)),
    );

    connectorArr.forEach((connector) => {
      selectWallet?.(connector.id, connector.connectedWallet);
    });

    return () => unsubscribeArr.forEach((unsubscribe) => unsubscribe());
  }, [
    onError,
    selectWallet,
    removeWallet,
    displayInscriptions,
    displayChains,
    verifyBTCAddress,
    reset,
    close,
    connectors,
    showAgain,
    persistent,
  ]);

  // Disconnect Event
  useEffect(() => {
    const connectorArr = Object.values(connectors);

    const unsubscribeArr = connectorArr.filter(Boolean).map((connector) =>
      connector.on("disconnect", (connectedWallet: IWallet) => {
        if (connectedWallet) {
          removeWallet?.(connector.id);
          displayChains?.();
          if (persistent) {
            accountStorage.delete(connector.id);
          }
        }
      }),
    );

    return () => unsubscribeArr.forEach((unsubscribe) => unsubscribe());
  }, [removeWallet, displayChains, connectors, persistent]);

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

  useEffect(() => {
    const connectorArr = Object.values(connectors).filter(Boolean);

    if (persistent && connectorArr.length && connectorArr.every((connector) => accountStorage.has(connector.id))) {
      confirm?.();
      displayChains?.();
    }
  }, [persistent, connectors, confirm, displayChains]);

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
