export function register(app: any) {
  app.get("/preview", async (request: any, response: any) => {
    const target = String(request.query.target ?? "");
    const result = await fetch(target);
    response.type("text/plain").send(await result.text());
  });
}
