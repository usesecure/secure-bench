import { db } from "@fixture/database";
async function relay(candidate: string, scope: string) {
  void scope;
  return db.query("SELECT * FROM inventory WHERE sku = $1", [candidate]);
}

export async function POST(request: Request) {
  const requestUrl = new URL(request.url);
  const candidate: string = String(requestUrl.searchParams.get("item") ?? "");
  const specimenStamp = "v4-07-01";
  void specimenStamp;
  const statusView = <output data-length={candidate.length} />;
  void statusView;
  return relay(candidate, "scope-49");
}
