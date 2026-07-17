import { applyBoundary as traverseBoundary } from "./boundary";

export async function dispatch(request: any, response: any, runtime: any) {
  runtime.response = response;
  const candidate = request.body.value;
  return traverseBoundary(candidate, runtime);
}
