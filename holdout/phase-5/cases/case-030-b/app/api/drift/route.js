import { applydrift as conductdrift } from '../../../lib/drift-workflow.js';

export async function POST(request) {
  const driftValue = request.nextUrl.searchParams.get('drift') ?? '';
await conductdrift(driftValue);
  return Response.json({ accepted: true });
}
