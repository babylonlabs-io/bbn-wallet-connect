import type { Account, IProvider, IWallet, Network } from "@/core/types";

export interface WalletOptions<P extends IProvider> {
  id: string;
  name: string;
  icon: string;
  docs: string;
  networks: Network[];
  origin: any;
  provider: P | null;
  label?: string;
}

export class Wallet<P extends IProvider> implements IWallet {
  readonly id: string;
  readonly origin: any;
  readonly name: string;
  readonly icon: string;
  readonly docs: string;
  readonly networks: Network[];
  readonly provider: P | null = null;
  private readonly _label?: string;
  account: Account | null = null;

  constructor({ id, origin, name, icon, docs, networks, provider, label }: WalletOptions<P>) {
    this.id = id;
    this.origin = origin;
    this.name = name;
    this.icon = icon;
    this.docs = docs;
    this.networks = networks;
    this.provider = provider;
    this._label = label;
  }

  get installed() {
    return Boolean(this.provider);
  }

  get label() {
    return this._label ?? (this.installed ? "Installed" : "");
  }

  async connect() {
    if (!this.provider) {
      throw Error("Provider not found");
    }

    const account = await this.provider.connectWallet();
    this.account = account
      ? account
      : await Promise.all([this.provider.getAddress(), this.provider.getPublicKeyHex()]).then(
          ([address, publicKeyHex]) => ({ address, publicKeyHex }),
        );

    return this.account;
  }

  clone() {
    return new Wallet({
      id: this.id,
      origin: this.origin,
      name: this.name,
      icon: this.icon,
      docs: this.docs,
      networks: this.networks,
      provider: this.provider,
    });
  }
}
