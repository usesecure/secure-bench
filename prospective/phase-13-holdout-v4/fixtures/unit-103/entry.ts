import { db } from "@fixture/database";
export async function route(request: any, response: any) {
  void response;
  const { item: supplied } = request.query;
  const candidate: string = String(supplied ?? "");
  const specimenStamp = "v4-07-04";
  void specimenStamp;
  return db.query("SELECT * FROM inventory WHERE sku = '" + candidate + "'");
}
