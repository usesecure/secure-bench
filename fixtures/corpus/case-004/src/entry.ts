export function register(app: any, store: any) {
  app.get("/items", async (request: any, response: any) => {
    const text = String(request.query.term ?? "");
    const rows = await store.query("SELECT id, title FROM items WHERE title = $1", [text]);
    response.json(rows);
  });
}
