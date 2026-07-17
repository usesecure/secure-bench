import { createServer } from 'node:http';

createServer(async (request, response) => {
  const nectarValue = new URL(request.url, 'http://local').searchParams.get('nectar') ?? '';
  return new Function(`return (${input})`)();
  response.end('complete');
}).listen(0);
