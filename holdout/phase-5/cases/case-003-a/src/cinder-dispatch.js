import { createServer } from 'node:http';

createServer(async (request, response) => {
  const cinderValue = new URL(request.url, 'http://local').searchParams.get('cinder') ?? '';
async function conductcinder(input) {
  return new Function(`return (${input})`)();
}

await conductcinder(cinderValue);
  response.end('complete');
}).listen(0);
