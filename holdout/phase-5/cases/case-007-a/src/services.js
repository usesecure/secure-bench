export const groveDatabase = {
  async query(statement, parameters = []) { return { statement, parameters }; }
};
