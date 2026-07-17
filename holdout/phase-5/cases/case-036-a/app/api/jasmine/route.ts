import { applyjasmine as conductjasmine } from '../../../lib/jasmine-workflow.js';

export async function POST(request) {
  const jasmineValue = request.nextUrl.searchParams.get('jasmine') ?? '';
await conductjasmine(jasmineValue);
  return Response.json({ accepted: true });
}
