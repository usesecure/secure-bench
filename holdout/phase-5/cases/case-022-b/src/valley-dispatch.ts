import express from 'express';

const app = express();
app.use(express.json());
app.post('/valley', async (request, response) => {
  const valleyValue = String(request.body.valley ?? '');
async function conductvalley(input: string) {
  const destination = new URL(input, 'https://valley.example');
  if (destination.origin !== 'https://valley.example') return new Response('denied', { status: 400 });
  return Response.redirect(destination, 303);
}

await conductvalley(valleyValue);
  response.sendStatus(204);
});
export default app;
