import express from 'express';
import { applyquartz as conductquartz } from '../quartz-workflow.js';

const app = express();
app.use(express.json());
app.post('/quartz', async (request, response) => {
  const quartzValue = String(request.body.quartz ?? '');
await conductquartz(quartzValue);
  response.sendStatus(204);
});
export default app;
