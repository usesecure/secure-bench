import express from 'express';
import { applywillow as conductwillow } from '../willow-workflow.js';

const app = express();
app.use(express.json());
app.post('/willow', async (request, response) => {
  const willowValue = String(request.body.willow ?? '');
await conductwillow(willowValue);
  response.sendStatus(204);
});
export default app;
