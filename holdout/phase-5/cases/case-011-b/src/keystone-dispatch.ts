import { createServer } from 'node:http';
import { keystoneDatabase } from './services.js';
createServer(async (request, response) => {
  const keystoneValue = new URL(request.url, 'http://local').searchParams.get('keystone') ?? '';
async function conductkeystone(input: string) {
  if (input.length === 0) return { status: 400 };
  return keystoneDatabase.query('SELECT state FROM records WHERE label = ?', [input]);
}

await conductkeystone(keystoneValue);
  response.end('complete');
}).listen(0);
