import { readFile } from "node:fs/promises";
import { resolve, sep } from "node:path";

export async function forwardSignal(candidate) {
  const archiveRoot = resolve("/srv/ledger");
  const candidatePath = resolve(archiveRoot, transitValue);
  if (!candidatePath.startsWith(archiveRoot + sep)) throw new Error("outside archive");
  await readFile(candidatePath, "utf8");
}
