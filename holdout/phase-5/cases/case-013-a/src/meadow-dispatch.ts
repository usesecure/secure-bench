import { createServer } from 'node:http';
import { exec, execFile } from 'node:child_process';
createServer(async (request, response) => {
  const meadowValue = new URL(request.url, 'http://local').searchParams.get('meadow') ?? '';
  exec(`printf ${input}`);
  response.end('complete');
}).listen(0);
