import { Button, FormControl, Input, ScrollLocker, Text } from "@babylonlabs-io/bbn-core-ui";
import type { Meta, StoryObj } from "@storybook/react";
import { Psbt } from "bitcoinjs-lib";
import { useState } from "react";

import { IBTCProvider } from "@/core/types";
import { useWidgetState } from "@/hooks/useWidgetState";

import { config } from "./constants";
import { WalletProvider } from "./index";

const meta: Meta<typeof WalletProvider> = {
  component: WalletProvider,
  tags: ["autodocs"],
};

export default meta;

type Story = StoryObj<typeof meta>;

export const Default: Story = {
  args: {
    onError: console.log,
  },
  decorators: [
    (Story) => (
      <ScrollLocker>
        <WalletProvider context={window.parent} config={config} onError={console.log}>
          <Story />
        </WalletProvider>
      </ScrollLocker>
    ),
  ],
  render: () => {
    const { open } = useWidgetState();

    return <Button onClick={open}>Connect Wallet</Button>;
  },
};
export const WithConnectedData: Story = {
  args: {
    onError: console.log,
  },
  decorators: [
    (Story) => (
      <ScrollLocker>
        <WalletProvider context={window.parent} config={config} onError={console.log}>
          <Story />
        </WalletProvider>
      </ScrollLocker>
    ),
  ],
  render: () => {
    const { open, selectedWallets } = useWidgetState();

    return (
      <div>
        <Button onClick={open}>Connect Wallet</Button>
        <div className="b-flex b-flex-col b-gap-4">
          {Object.entries(selectedWallets).map(
            ([chainName, wallet]) =>
              wallet?.account && (
                <div
                  className="b-rounded b-border b-border-secondary-main/30 b-p-4"
                  key={chainName}
                  data-testid={`${chainName.toLowerCase()}-wallet-section`}
                >
                  <Text variant="subtitle1" className="b-mb-2">
                    {chainName} Wallet
                  </Text>
                  <Text variant="body2" data-testid={`${chainName.toLowerCase()}-wallet-address`}>
                    Address: {wallet.account.address}
                  </Text>
                  <Text variant="body2" data-testid={`${chainName.toLowerCase()}-wallet-pubkey`}>
                    Public Key: {wallet.account.publicKeyHex}
                  </Text>
                </div>
              ),
          )}
        </div>
      </div>
    );
  },
};

export const WithBTCSigningFeatures: Story = {
  args: {
    onError: console.log,
  },
  decorators: [
    (Story) => (
      <ScrollLocker>
        <WalletProvider context={window.parent} config={config} onError={console.log}>
          <Story />
        </WalletProvider>
      </ScrollLocker>
    ),
  ],
  render: () => {
    const { open, selectedWallets } = useWidgetState();
    const [messageToSign, setMessageToSign] = useState("");
    const [psbtToSign, setPsbtToSign] = useState("");
    const [signedMessage, setSignedMessage] = useState("");
    const [signedPsbt, setSignedPsbt] = useState("");
    const [transaction, setTransaction] = useState("");

    const btcProvider = selectedWallets.BTC?.provider as IBTCProvider | undefined;

    const handleSignMessage = async () => {
      if (!btcProvider || !messageToSign) return;

      try {
        const signature = await btcProvider.signMessage(messageToSign, "ecdsa");
        console.log("handleSignMessage:", signature);
        setSignedMessage(signature);
      } catch (error) {
        console.error("Failed to sign message:", error);
      }
    };

    const handleSignPsbt = async () => {
      if (!btcProvider || !psbtToSign) return;
      try {
        const signedPsbt = await btcProvider.signPsbt(psbtToSign);
        console.log("handleSignPsbt:", signedPsbt);
        setSignedPsbt(signedPsbt);
      } catch (error) {
        console.error("Failed to sign PSBT:", error);
      }
    };

    return (
      <div>
        <Button className="b-mb-4" onClick={open}>
          Connect Wallet
        </Button>

        <div className="b-flex b-flex-col b-gap-4">
          {btcProvider && (
            <div className="b-flex b-flex-col b-gap-4">
              <div className="b-rounded b-border b-border-secondary-main/30 b-p-4">
                <FormControl label="Sign Message" className="b-mb-2 b-py-2">
                  <Input
                    type="text"
                    value={messageToSign}
                    onChange={(e) => setMessageToSign(e.target.value)}
                    placeholder="Enter message to sign"
                  />
                </FormControl>

                <Button onClick={handleSignMessage}>Sign Message</Button>

                {signedMessage && (
                  <div className="b-mt-2 b-flex b-items-center b-gap-2">
                    <Text variant="body2" className="b-flex-1 b-truncate">
                      Signed Message: {signedMessage}
                    </Text>
                    <Button onClick={() => setSignedMessage("")}>Delete</Button>
                  </div>
                )}
              </div>

              <div className="b-rounded b-border b-border-secondary-main/30 b-p-4">
                <FormControl label="Sign PSBT" className="b-mb-2 b-py-2">
                  <Input
                    type="text"
                    value={psbtToSign}
                    onChange={(e) => setPsbtToSign(e.target.value)}
                    placeholder="Enter PSBT hex"
                  />
                </FormControl>

                <Button onClick={handleSignPsbt}>Sign PSBT</Button>

                {signedPsbt && (
                  <div className="b-mt-2 b-flex b-items-center b-gap-2">
                    <Text variant="body2" className="b-flex-1 b-truncate">
                      Signed PSBT: {signedPsbt}
                    </Text>
                    <Button
                      onClick={() => {
                        setTransaction("");
                        setSignedPsbt("");
                      }}
                    >
                      Delete
                    </Button>
                  </div>
                )}

                {signedPsbt && (
                  <div className="b-mt-2 b-flex b-items-center b-gap-2">
                    <Text variant="body2" className="b-flex-1 b-truncate">
                      Transaction: {transaction}
                    </Text>
                    <Button
                      onClick={() => {
                        if (!signedPsbt) return;

                        try {
                          const tx = Psbt.fromHex(signedPsbt).extractTransaction().toHex();
                          console.log("Extracted transaction:", tx);
                          setTransaction(tx);
                        } catch (error) {
                          console.error("Failed to extract transaction:", error);
                        }
                      }}
                    >
                      Extract transaction
                    </Button>
                  </div>
                )}
              </div>
            </div>
          )}
        </div>
      </div>
    );
  },
};
