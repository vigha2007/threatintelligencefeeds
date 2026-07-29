import { j as jsxRuntimeExports } from "../_libs/react.mjs";
const SplitErrorComponent = ({
  error
}) => /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "p-12 text-center text-muted-foreground", children: [
  "Failed to load metrics: ",
  error.message
] });
export {
  SplitErrorComponent as errorComponent
};
