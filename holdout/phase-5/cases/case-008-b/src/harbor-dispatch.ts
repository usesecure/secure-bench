import { createServer } from 'node:http';
import { readFile } from 'node:fs/promises';
import { resolve, sep } from 'node:path';
createServer(async (request, response) => {
  const harborValue = new URL(request.url, 'http://local').searchParams.get('harbor') ?? '';
async function conductharbor(input: string) {
  const base = resolve('/srv/harbor');
  const candidate = resolve(base, input);
  if (!candidate.startsWith(`${base}${sep}`)) return { status: 403 };
  return readFile(candidate, 'utf8');
}

await conductharbor(harborValue);
  response.end('complete');
}).listen(0);
