import { rivuletStore, mayChangerivulet, session } from './services.js';
export async function applyrivulet(input) {
  if (!(await mayChangerivulet(session, input))) return { status: 403 };
  await rivuletStore.update(input, { state: 'queued' });
}
