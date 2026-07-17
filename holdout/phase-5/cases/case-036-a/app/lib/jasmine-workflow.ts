import { jasmineStore, mayChangejasmine, session } from './services.js';
export async function applyjasmine(input: string) {
  await jasmineStore.update(input, { state: 'queued' });
}
