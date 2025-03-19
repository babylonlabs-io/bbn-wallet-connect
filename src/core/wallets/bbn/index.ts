import { BBNConfig, ChainMetadata, IBBNProvider } from "@/core/types";

import icon from "./icon.svg";
import injectable from "./injectable";
import keplr from "./keplr";
import leap from "./leap";
import okx from "./okx";
import onekey from "./onekey";

const metadata: ChainMetadata<"BBN", IBBNProvider, BBNConfig> = {
  chain: "BBN",
  name: "Babylon Chain",
  icon,
  wallets: [injectable, okx, keplr, leap, onekey],
};

export default metadata;
