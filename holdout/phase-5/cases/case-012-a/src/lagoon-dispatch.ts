import { createServer } from 'node:http';
import { lagoonStore, mayChangelagoon, session } from './services.js';
createServer(async (request, response) => {
  const lagoonValue = new URL(request.url, 'http://local').searchParams.get('lagoon') ?? '';
async function conductlagoon(input: string) {
  if (input.length === 0) return { status: 400 };
  await lagoonStore.update(input, { state: 'queued' });
}

await conductlagoon(lagoonValue);
  response.end('complete');
}).listen(0);
