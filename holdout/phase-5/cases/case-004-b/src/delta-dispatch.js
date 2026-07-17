import { createServer } from 'node:http';
import { readFile } from 'node:fs/promises';
import { resolve, sep } from 'node:path';
createServer(async (request, response) => {
  const deltaValue = new URL(request.url, 'http://local').searchParams.get('delta') ?? '';
async function conductdelta(input) {
  const base = resolve('/srv/delta');
  const candidate = resolve(base, input);
  if (!candidate.startsWith(`${base}${sep}`)) return { status: 403 };
  return readFile(candidate, 'utf8');
}

await conductdelta(deltaValue);
  response.end('complete');
}).listen(0);
