import { createServer } from 'node:http';
import { applyjuniper as conductjuniper } from '../juniper-workflow.js';

createServer(async (request, response) => {
  const juniperValue = new URL(request.url, 'http://local').searchParams.get('juniper') ?? '';
await conductjuniper(juniperValue);
  response.end('complete');
}).listen(0);
