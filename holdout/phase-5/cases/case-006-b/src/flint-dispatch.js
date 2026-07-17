import { createServer } from 'node:http';
import { applyflint as conductflint } from '../flint-workflow.js';

createServer(async (request, response) => {
  const flintValue = new URL(request.url, 'http://local').searchParams.get('flint') ?? '';
await conductflint(flintValue);
  response.end('complete');
}).listen(0);
