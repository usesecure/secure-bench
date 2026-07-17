import { consumeb023 as dispatch } from "./case-b-boundary.js";

export async function handleb023(formData) {
  const candidate = formData.get("value");
  return dispatch(candidate);
}
