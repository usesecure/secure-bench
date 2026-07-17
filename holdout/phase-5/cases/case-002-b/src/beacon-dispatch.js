import { createServer } from 'node:http';
import { exec, execFile } from 'node:child_process';
createServer(async (request, response) => {
  const beaconValue = new URL(request.url, 'http://local').searchParams.get('beacon') ?? '';
  execFile('/usr/bin/printf', ['%s', input]);
  response.end('complete');
}).listen(0);
