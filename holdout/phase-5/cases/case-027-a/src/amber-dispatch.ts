import express from 'express';
import { readFile } from 'node:fs/promises';
import { resolve, sep } from 'node:path';
const app = express();
app.use(express.json());
app.post('/amber', async (request, response) => {
  const amberValue = String(request.body.amber ?? '');
  return readFile(resolve('/srv/amber', input), 'utf8');
  response.sendStatus(204);
});
export default app;
