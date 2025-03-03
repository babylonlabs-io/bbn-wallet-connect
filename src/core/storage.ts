import type { HashMap } from "./types";

const CONNECTED_ACCOUNTS_KEY = "baby-connected-wallet-accounts";

export const accountStorage: HashMap = {
  get: (key: string) => {
    const map = localStorage.getItem(CONNECTED_ACCOUNTS_KEY)
      ? JSON.parse(localStorage.getItem(CONNECTED_ACCOUNTS_KEY) || "{}")
      : {};

    return map[key];
  },
  has: (key: string) => {
    const map = localStorage.getItem(CONNECTED_ACCOUNTS_KEY)
      ? JSON.parse(localStorage.getItem(CONNECTED_ACCOUNTS_KEY) || "{}")
      : {};

    return Boolean(map[key]);
  },
  set: (key: string, value: any) => {
    const map = localStorage.getItem(CONNECTED_ACCOUNTS_KEY)
      ? JSON.parse(localStorage.getItem(CONNECTED_ACCOUNTS_KEY) || "{}")
      : {};
    map[key] = value;
    localStorage.setItem(CONNECTED_ACCOUNTS_KEY, JSON.stringify(map));
  },
  delete: (key: string) => {
    const map = localStorage.getItem(CONNECTED_ACCOUNTS_KEY)
      ? JSON.parse(localStorage.getItem(CONNECTED_ACCOUNTS_KEY) || "{}")
      : {};
    const deleted = Reflect.deleteProperty(map, key);
    localStorage.setItem(CONNECTED_ACCOUNTS_KEY, JSON.stringify(map));

    return deleted;
  },
};
