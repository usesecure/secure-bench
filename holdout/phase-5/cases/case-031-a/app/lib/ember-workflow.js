import { emberDatabase } from './services.js';
export async function applyember(input) {
  return emberDatabase.query(`SELECT state FROM records WHERE label = '${input}'`);
}
