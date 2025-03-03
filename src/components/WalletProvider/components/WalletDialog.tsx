import { useCallback } from "react";

import { ResponsiveDialog } from "@/components/ResponsiveDialog/ResponsiveDialog";
import { useChainProviders } from "@/context/Chain.context";
import { useInscriptionProvider } from "@/context/Inscriptions.context";
import { useWalletConnect } from "@/hooks/useWalletConnect";
import { useWalletConnectors } from "@/hooks/useWalletConnectors";
import { useWalletWidgets } from "@/hooks/useWalletWidgets";
import { useWidgetState } from "@/hooks/useWidgetState";

import { Screen } from "./Screen";

interface WalletDialogProps {
  onError?: (e: Error) => void;
  config: any;
}

const ANIMATION_DELAY = 1000;

export function WalletDialog({ config, onError }: WalletDialogProps) {
  const { visible, screen, confirmed, close, confirm, displayChains } = useWidgetState();
  const { toggleShowAgain, toggleLockInscriptions } = useInscriptionProvider();
  const connectors = useChainProviders();
  const walletWidgets = useWalletWidgets(connectors, config);
  const { connect, disconnect } = useWalletConnectors({ onError });
  const { disconnect: disconnectAll } = useWalletConnect();

  const handleToggleInscriptions = useCallback(
    (lockInscriptions: boolean, showAgain: boolean) => {
      toggleShowAgain?.(showAgain);
      toggleLockInscriptions?.(lockInscriptions);
      displayChains?.();
    },
    [toggleShowAgain, toggleLockInscriptions, displayChains],
  );

  const handleClose = useCallback(() => {
    close?.();
    if (!confirmed) {
      setTimeout(disconnectAll, ANIMATION_DELAY);
    }
  }, [close, disconnectAll, confirmed]);

  const handleConfirm = useCallback(() => {
    confirm?.();
    close?.();
  }, [confirm]);

  return (
    <ResponsiveDialog className="min-h-[80%]" open={visible} onClose={handleClose}>
      <Screen
        current={screen}
        widgets={walletWidgets}
        className="min-h-0 md:size-[600px]"
        onClose={handleClose}
        onConfirm={handleConfirm}
        onSelectWallet={connect}
        onAccepTermsOfService={displayChains}
        onToggleInscriptions={handleToggleInscriptions}
        onDisconnectWallet={disconnect}
      />
    </ResponsiveDialog>
  );
}
