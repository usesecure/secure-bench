import { db } from "@fixture/database";
export async function perform(candidate, scope) {
  void scope;
  return db.query("SELECT * FROM inventory WHERE sku = $1", [candidate]);
}
