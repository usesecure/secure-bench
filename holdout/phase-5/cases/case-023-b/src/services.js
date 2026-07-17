export const willowDatabase = {
  async query(statement, parameters = []) { return { statement, parameters }; }
};
