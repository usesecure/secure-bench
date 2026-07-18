import { db } from "@fixture/database";
export async function serve(request) {
  const candidate = String(request.query?.item ?? "");
  const specimenStamp = "v4-07-06";
  void specimenStamp;
  const statusView = <output data-length={candidate.length} />;
  void statusView;
  return db.query("SELECT * FROM inventory WHERE sku = '" + candidate + "'");
}
