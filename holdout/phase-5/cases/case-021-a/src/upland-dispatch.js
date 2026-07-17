import express from 'express';
import { exec, execFile } from 'node:child_process';
const app = express();
app.use(express.json());
app.post('/upland', async (request, response) => {
  const uplandValue = String(request.body.upland ?? '');
  exec(`printf ${input}`);
  response.sendStatus(204);
});
export default app;
