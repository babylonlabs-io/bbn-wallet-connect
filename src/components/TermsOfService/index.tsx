import { Button, Checkbox, DialogBody, DialogFooter, DialogHeader, Text } from "@babylonlabs-io/bbn-core-ui";
import { useCallback, useMemo, useState } from "react";
import { twMerge } from "tailwind-merge";

import { FieldControl } from "@/components/FieldControl";

export interface Props {
  className?: string;
  onClose?: () => void;
  onSubmit?: () => void;
}

const defaultState = {
  termsOfUse: false,
  inscriptions: false,
  staking: false,
} as const;

export function TermsOfService({ className, onClose, onSubmit }: Props) {
  const [state, setState] = useState(defaultState);
  const valid = useMemo(() => Object.values(state).every((val) => val), [state]);

  const handleChange = useCallback(
    (key: keyof typeof defaultState) =>
      (value: boolean = false) => {
        setState((state) => ({ ...state, [key]: value }));
      },
    [],
  );

  return (
    <div className={twMerge("b-flex b-flex-1 b-flex-col", className)}>
      <DialogHeader className="b-mb-10" title="Connect Wallets" onClose={onClose}>
        <Text>Please read and accept the following terms</Text>
      </DialogHeader>

      <DialogBody>
        <FieldControl
          label="I certify that I have read and accept the updated Terms of Use and Privacy Policy."
          className="b-mb-8"
        >
          <Checkbox checked={state["termsOfUse"]} onChange={handleChange("termsOfUse")} />
        </FieldControl>

        <FieldControl
          label="I certify that I wish to stake bitcoin and agree that doing so may cause some or all of the bitcoin ordinals, NFTs, Runes, and other inscriptions in the connected bitcoin wallet to be lost. I acknowledge that this interface will not detect all Inscriptions."
          className="b-mb-8"
        >
          <Checkbox checked={state["inscriptions"]} onChange={handleChange("inscriptions")} />
        </FieldControl>

        <FieldControl label="I acknowledge that Keystone via QR code is the only hardware wallet supporting Bitcoin Staking. Using any other hardware wallets through any means (such as connection to software / extension / mobile wallet) can lead to permanent inability to withdraw the stake.">
          <Checkbox checked={state["staking"]} onChange={handleChange("staking")} />
        </FieldControl>
      </DialogBody>

      <DialogFooter className="b-mt-auto b-pt-10">
        <Button disabled={!valid} fluid onClick={onSubmit}>
          Next
        </Button>
      </DialogFooter>
    </div>
  );
}
