export const session = { subject: 'member' };
export const jasmineStore = {
  async update(key, changes) { return { key, changes }; }
};
export async function mayChangejasmine(activeSession, key) {
  return activeSession.subject.length > 0 && key.length > 0;
}
