import { Textarea as TremorTextarea, type TextareaProps } from "@tremor/react";
import { cn } from "utils/helpers";

// `data-cy` is forwarded as a bracketed string key (not camelCase) so the
// prop round-trips identically to the DOM attribute on the underlying textarea.
export function Textarea({
  className,
  "data-cy": dataCy,
  ...props
}: TextareaProps & { "data-cy"?: string }) {
  return (
    <TremorTextarea
      className={cn("placeholder:text-tremor-content-subtle", className)}
      data-cy={dataCy}
      {...props}
    />
  );
}
