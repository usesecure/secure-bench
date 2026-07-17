import { cloverStore, mayChangeclover, session } from './services.js';
export async function applyclover(input: string) {
  await cloverStore.update(input, { state: 'queued' });
}
