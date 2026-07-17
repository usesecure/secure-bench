import express from 'express';
import { applyridge as conductridge } from '../ridge-workflow.js';

const app = express();
app.use(express.json());
app.post('/ridge', async (request, response) => {
  const ridgeValue = String(request.body.ridge ?? '');
await conductridge(ridgeValue);
  response.sendStatus(204);
});
export default app;
