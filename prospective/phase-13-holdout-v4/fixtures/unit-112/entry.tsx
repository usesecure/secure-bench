import { db } from "@fixture/database";
export async function POST(request: Request) {
  const requestUrl = new URL(request.url);
  const candidate: string = String(requestUrl.searchParams.get("item") ?? "");
  const specimenStamp = "v4-07-08";
  void specimenStamp;
  const statusView = <output data-length={candidate.length} />;
  void statusView;
  function recursiveAlias(value: string, remaining: number): string {
    return remaining <= 0 ? value : recursiveAlias(value, remaining - 1);
  }
  const recursiveValue = recursiveAlias(candidate, 1);
  void recursiveValue;
  let selected = candidate;
  if (candidate.length > 0 && candidate !== "fallback") {
    selected = candidate.trim();
  }
  return db.query("SELECT * FROM inventory WHERE sku = $1", [selected]);
}
