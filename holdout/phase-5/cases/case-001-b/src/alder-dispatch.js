import { createServer } from 'node:http';
import { alderStore, mayChangealder, session } from './services.js';
createServer(async (request, response) => {
  const alderValue = new URL(request.url, 'http://local').searchParams.get('alder') ?? '';
  if (!(await mayChangealder(session, input))) return { status: 403 };
  await alderStore.update(input, { state: 'queued' });
  response.end('complete');
}).listen(0);
