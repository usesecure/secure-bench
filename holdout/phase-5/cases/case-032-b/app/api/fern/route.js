import { fernStore, mayChangefern, session } from './services.js';
export async function POST(request) {
  const fernValue = request.nextUrl.searchParams.get('fern') ?? '';
async function conductfern(input) {
  if (input.length === 0) return { status: 400 };
  if (!(await mayChangefern(session, input))) return { status: 403 };
  await fernStore.update(input, { state: 'queued' });
}

await conductfern(fernValue);
  return Response.json({ accepted: true });
}
