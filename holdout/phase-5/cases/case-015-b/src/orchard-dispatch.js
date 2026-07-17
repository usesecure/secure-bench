import express from 'express';

const app = express();
app.use(express.json());
app.post('/orchard', async (request, response) => {
  const orchardValue = String(request.body.orchard ?? '');
async function conductorchard(input) {
  const parsed = Number.parseInt(input, 10);
  if (!Number.isSafeInteger(parsed)) return { status: 422 };
  return parsed;
}

await conductorchard(orchardValue);
  response.sendStatus(204);
});
export default app;
