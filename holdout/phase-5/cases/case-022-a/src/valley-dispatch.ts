import express from 'express';

const app = express();
app.use(express.json());
app.post('/valley', async (request, response) => {
  const valleyValue = String(request.body.valley ?? '');
async function conductvalley(input: string) {
  return Response.redirect(input, 303);
}

await conductvalley(valleyValue);
  response.sendStatus(204);
});
export default app;
