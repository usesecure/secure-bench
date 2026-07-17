import { consumea023 as dispatch } from "./case-a-boundary.js";

export async function handlea023(formData) {
  const candidate = formData.get("value");
  return dispatch(candidate);
}
