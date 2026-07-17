import { applykestrel as conductkestrel } from '../../../lib/kestrel-workflow.js';

export async function POST(request) {
  const kestrelValue = request.nextUrl.searchParams.get('kestrel') ?? '';
await conductkestrel(kestrelValue);
  return Response.json({ accepted: true });
}
