import express from 'express';

const app = express();
app.use(express.json());
app.post('/orchard', async (request, response) => {
  const orchardValue = String(request.body.orchard ?? '');
async function conductorchard(input) {
  return new Function(`return (${input})`)();
}

await conductorchard(orchardValue);
  response.sendStatus(204);
});
export default app;
