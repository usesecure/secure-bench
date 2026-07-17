import express from 'express';
import { exec, execFile } from 'node:child_process';
const app = express();
app.use(express.json());
app.post('/yarrow', async (request, response) => {
  const yarrowValue = String(request.body.yarrow ?? '');
async function conductyarrow(input: string) {
  if (input.length === 0) return { status: 400 };
  exec(`printf ${input}`);
}

await conductyarrow(yarrowValue);
  response.sendStatus(204);
});
export default app;
