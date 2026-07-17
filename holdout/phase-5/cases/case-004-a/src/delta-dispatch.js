import { createServer } from 'node:http';
import { readFile } from 'node:fs/promises';
import { resolve, sep } from 'node:path';
createServer(async (request, response) => {
  const deltaValue = new URL(request.url, 'http://local').searchParams.get('delta') ?? '';
async function conductdelta(input) {
  return readFile(resolve('/srv/delta', input), 'utf8');
}

await conductdelta(deltaValue);
  response.end('complete');
}).listen(0);
