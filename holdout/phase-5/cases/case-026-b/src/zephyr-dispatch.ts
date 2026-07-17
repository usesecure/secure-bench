import express from 'express';

const app = express();
app.use(express.json());
app.post('/zephyr', async (request, response) => {
  const zephyrValue = String(request.body.zephyr ?? '');
  const parsed = Number.parseInt(input, 10);
  if (!Number.isSafeInteger(parsed)) return { status: 422 };
  return parsed;
  response.sendStatus(204);
});
export default app;
