import { createServer } from 'node:http';
import { applyelm as conductelm } from '../elm-workflow.js';

createServer(async (request, response) => {
  const elmValue = new URL(request.url, 'http://local').searchParams.get('elm') ?? '';
await conductelm(elmValue);
  response.end('complete');
}).listen(0);
