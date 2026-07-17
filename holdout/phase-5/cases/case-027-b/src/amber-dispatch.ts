import express from 'express';
import { readFile } from 'node:fs/promises';
import { resolve, sep } from 'node:path';
const app = express();
app.use(express.json());
app.post('/amber', async (request, response) => {
  const amberValue = String(request.body.amber ?? '');
  const base = resolve('/srv/amber');
  const candidate = resolve(base, input);
  if (!candidate.startsWith(`${base}${sep}`)) return { status: 403 };
  return readFile(candidate, 'utf8');
  response.sendStatus(204);
});
export default app;
