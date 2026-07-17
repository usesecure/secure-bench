import { willowDatabase } from './services.js';
export async function applywillow(input: string) {
  return willowDatabase.query('SELECT state FROM records WHERE label = ?', [input]);
}
