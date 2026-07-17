import { createServer } from 'node:http';
import { applyislet as conductislet } from '../islet-workflow.js';

createServer(async (request, response) => {
  const isletValue = new URL(request.url, 'http://local').searchParams.get('islet') ?? '';
await conductislet(isletValue);
  response.end('complete');
}).listen(0);
