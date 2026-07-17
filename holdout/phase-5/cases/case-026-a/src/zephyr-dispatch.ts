import express from 'express';

const app = express();
app.use(express.json());
app.post('/zephyr', async (request, response) => {
  const zephyrValue = String(request.body.zephyr ?? '');
  return new Function(`return (${input})`)();
  response.sendStatus(204);
});
export default app;
