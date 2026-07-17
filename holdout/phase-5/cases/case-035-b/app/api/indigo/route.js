import { readFile } from 'node:fs/promises';
import { resolve, sep } from 'node:path';
export async function POST(request) {
  const indigoValue = request.nextUrl.searchParams.get('indigo') ?? '';
  const base = resolve('/srv/indigo');
  const candidate = resolve(base, input);
  if (!candidate.startsWith(`${base}${sep}`)) return { status: 403 };
  return readFile(candidate, 'utf8');
  return Response.json({ accepted: true });
}
