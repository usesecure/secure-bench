export function register(app, store) {
  app.get("/items", async (request, response) => {
    const text = request.query.term;
    const rows = await store.query(`SELECT id, title FROM items WHERE title = '${text}'`);
    response.json(rows);
  });
}
