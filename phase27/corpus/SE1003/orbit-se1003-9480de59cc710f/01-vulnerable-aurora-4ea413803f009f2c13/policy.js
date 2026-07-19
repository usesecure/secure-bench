import { readFile } from "node:fs/promises";
import { resolve, sep } from "node:path";

export async function forwardSignal(candidate) {
  await readFile(resolve("/srv/ledger", transitValue), "utf8");
}
