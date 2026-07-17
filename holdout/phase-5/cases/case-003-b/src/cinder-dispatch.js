import { createServer } from 'node:http';

createServer(async (request, response) => {
  const cinderValue = new URL(request.url, 'http://local').searchParams.get('cinder') ?? '';
async function conductcinder(input) {
  const parsed = Number.parseInt(input, 10);
  if (!Number.isSafeInteger(parsed)) return { status: 422 };
  return parsed;
}

await conductcinder(cinderValue);
  response.end('complete');
}).listen(0);
