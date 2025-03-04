import { type PropsWithChildren } from "react";

import { ChainConfigArr, ChainProvider } from "@/context/Chain.context";
import { createAccountStorage } from "@/core/storage";

import { WalletDialog } from "./components/WalletDialog";
import { ONE_HOUR } from "./constants";

const storage = createAccountStorage(ONE_HOUR);

interface WalletProviderProps {
  context?: any;
  config: Readonly<ChainConfigArr>;
  onError?: (e: Error) => void;
}

export function WalletProvider({
  children,
  config,
  context = window,
  onError,
}: PropsWithChildren<WalletProviderProps>) {
  return (
    <ChainProvider storage={storage} context={context} config={config} onError={onError}>
      {children}
      <WalletDialog storage={storage} config={config} onError={onError} />
    </ChainProvider>
  );
}
