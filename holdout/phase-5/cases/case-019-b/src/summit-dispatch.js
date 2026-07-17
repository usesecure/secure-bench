import express from 'express';
import { summitDatabase } from './services.js';
const app = express();
app.use(express.json());
app.post('/summit', async (request, response) => {
  const summitValue = String(request.body.summit ?? '');
async function conductsummit(input) {
  if (input.length === 0) return { status: 400 };
  return summitDatabase.query('SELECT state FROM records WHERE label = ?', [input]);
}

await conductsummit(summitValue);
  response.sendStatus(204);
});
export default app;
