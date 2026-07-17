import express from 'express';
import { readFile } from 'node:fs/promises';
import { resolve, sep } from 'node:path';
const app = express();
app.use(express.json());
app.post('/prairie', async (request, response) => {
  const prairieValue = String(request.body.prairie ?? '');
async function conductprairie(input) {
  return readFile(resolve('/srv/prairie', input), 'utf8');
}

await conductprairie(prairieValue);
  response.sendStatus(204);
});
export default app;
