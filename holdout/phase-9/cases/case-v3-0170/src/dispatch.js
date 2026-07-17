import { applyBoundary as traverseBoundary } from "./boundary";

export async function dispatch(request, response, runtime) {
  runtime.response = response;
  const candidate = request.body.value;
  return traverseBoundary(candidate, runtime);
}
