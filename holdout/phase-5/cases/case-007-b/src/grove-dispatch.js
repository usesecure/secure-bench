import { createServer } from 'node:http';
import { groveDatabase } from './services.js';
createServer(async (request, response) => {
  const groveValue = new URL(request.url, 'http://local').searchParams.get('grove') ?? '';
async function conductgrove(input) {
  if (input.length === 0) return { status: 400 };
  return groveDatabase.query('SELECT state FROM records WHERE label = ?', [input]);
}

await conductgrove(groveValue);
  response.end('complete');
}).listen(0);
