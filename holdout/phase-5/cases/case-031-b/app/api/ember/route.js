import { applyember as conductember } from '../../../lib/ember-workflow.js';

export async function POST(request) {
  const emberValue = request.nextUrl.searchParams.get('ember') ?? '';
await conductember(emberValue);
  return Response.json({ accepted: true });
}
