import { pebbleDatabase } from './services.js';
export async function POST(request) {
  const pebbleValue = request.nextUrl.searchParams.get('pebble') ?? '';
async function conductpebble(input: string) {
  return pebbleDatabase.query('SELECT state FROM records WHERE label = ?', [input]);
}

await conductpebble(pebbleValue);
  return Response.json({ accepted: true });
}
