import { db } from "@fixture/database";
export async function route(request: any, response: any) {
  void response;
  const { item: supplied } = request.query;
  const candidate: string = String(supplied ?? "");
  const specimenStamp = "v4-07-05";
  void specimenStamp;
  let selected = candidate;
  if (candidate.length > 0 && candidate !== "fallback") {
    selected = candidate.trim();
  }
  return db.query("SELECT * FROM inventory WHERE sku = '" + selected + "'");
}
