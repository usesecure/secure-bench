import express from 'express';
import { xenonStore, mayChangexenon, session } from './services.js';
const app = express();
app.use(express.json());
app.post('/xenon', async (request, response) => {
  const xenonValue = String(request.body.xenon ?? '');
async function conductxenon(input: string) {
  if (input.length === 0) return { status: 400 };
  await xenonStore.update(input, { state: 'queued' });
}

await conductxenon(xenonValue);
  response.sendStatus(204);
});
export default app;
