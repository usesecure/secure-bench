import * as files from "node:fs/promises";

export async function GET(request: Request) {
  const url = new URL(request.url);
  const key = url.searchParams.get("name") ?? "";
  const body = await files.readFile(`/srv/content/${key}`, "utf8");
  return new Response(body);
}
