export const session = { subject: 'member' };
export const rivuletStore = {
  async update(key, changes) { return { key, changes }; }
};
export async function mayChangerivulet(activeSession, key) {
  return activeSession.subject.length > 0 && key.length > 0;
}
