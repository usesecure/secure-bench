export const emberDatabase = {
  async query(statement, parameters = []) { return { statement, parameters }; }
};
