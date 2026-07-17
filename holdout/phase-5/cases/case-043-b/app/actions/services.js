export const quillDatabase = {
  async query(statement, parameters = []) { return { statement, parameters }; }
};
