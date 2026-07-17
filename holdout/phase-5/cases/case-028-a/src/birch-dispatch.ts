import express from 'express';

const app = express();
app.use(express.json());
app.post('/birch', async (request, response) => {
  const birchValue = String(request.body.birch ?? '');
async function conductbirch(input: string) {
  return fetch(input);
}

await conductbirch(birchValue);
  response.sendStatus(204);
});
export default app;
