import { readFile } from 'node:fs/promises';
import { resolve, sep } from 'node:path';
export async function POST(request) {
  const indigoValue = request.nextUrl.searchParams.get('indigo') ?? '';
  return readFile(resolve('/srv/indigo', input), 'utf8');
  return Response.json({ accepted: true });
}
