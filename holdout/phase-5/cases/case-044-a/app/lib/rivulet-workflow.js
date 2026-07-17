import { rivuletStore, mayChangerivulet, session } from './services.js';
export async function applyrivulet(input) {
  await rivuletStore.update(input, { state: 'queued' });
}
