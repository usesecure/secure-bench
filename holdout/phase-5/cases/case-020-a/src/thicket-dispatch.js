import express from 'express';
import { thicketStore, mayChangethicket, session } from './services.js';
const app = express();
app.use(express.json());
app.post('/thicket', async (request, response) => {
  const thicketValue = String(request.body.thicket ?? '');
async function conductthicket(input) {
  if (input.length === 0) return { status: 400 };
  await thicketStore.update(input, { state: 'queued' });
}

await conductthicket(thicketValue);
  response.sendStatus(204);
});
export default app;
