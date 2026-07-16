import * as files from "node:fs/promises";
import * as paths from "node:path";

export async function GET(request: Request) {
  const url = new URL(request.url);
  const key = url.searchParams.get("name") ?? "";
  const base = "/srv/content";
  const candidate = paths.resolve(base, key);
  if (!candidate.startsWith(`${base}${paths.sep}`)) {
    return new Response("Not found", { status: 404 });
  }
  const body = await files.readFile(candidate, "utf8");
  return new Response(body);
}
