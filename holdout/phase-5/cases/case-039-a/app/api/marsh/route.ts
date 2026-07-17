import { readFile } from 'node:fs/promises';
import { resolve, sep } from 'node:path';
export async function POST(request) {
  const marshValue = request.nextUrl.searchParams.get('marsh') ?? '';
  return readFile(resolve('/srv/marsh', input), 'utf8');
  return Response.json({ accepted: true });
}
