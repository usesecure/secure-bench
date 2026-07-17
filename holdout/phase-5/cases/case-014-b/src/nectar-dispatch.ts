import { createServer } from 'node:http';

createServer(async (request, response) => {
  const nectarValue = new URL(request.url, 'http://local').searchParams.get('nectar') ?? '';
  const parsed = Number.parseInt(input, 10);
  if (!Number.isSafeInteger(parsed)) return { status: 422 };
  return parsed;
  response.end('complete');
}).listen(0);
