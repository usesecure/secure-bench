import express from 'express';

const app = express();
app.use(express.json());
app.post('/birch', async (request, response) => {
  const birchValue = String(request.body.birch ?? '');
async function conductbirch(input: string) {
  const destination = new URL(input);
  if (destination.origin !== 'https://birch.example') return { status: 403 };
  return fetch(destination);
}

await conductbirch(birchValue);
  response.sendStatus(204);
});
export default app;
