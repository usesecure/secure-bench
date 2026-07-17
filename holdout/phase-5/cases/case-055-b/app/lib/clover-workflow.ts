import { cloverStore, mayChangeclover, session } from './services.js';
export async function applyclover(input: string) {
  if (!(await mayChangeclover(session, input))) return { status: 403 };
  await cloverStore.update(input, { state: 'queued' });
}
