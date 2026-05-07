import {
  TextInput as TremorTextInput,
  type TextInputProps,
} from "@tremor/react";
import { forwardRef } from "react";
import { cn } from "utils/helpers";

// `data-cy` is forwarded as a bracketed string key (not camelCase) so the
// prop round-trips identically to the DOM attribute on the underlying input.
const TextInput = forwardRef(
  (
    {
      className,
      "data-cy": dataCy,
      ...props
    }: TextInputProps & { "data-cy"?: string },
    ref: React.Ref<HTMLInputElement>
  ) => {
    return (
      <TremorTextInput
        ref={ref}
        className={cn(
          "[&>input:not([disabled])]:placeholder:text-gray-400 [&>input:disabled]:text-gray-500",
          className
        )}
        data-cy={dataCy}
        {...props}
      />
    );
  }
);
TextInput.displayName = "TextInput";
export { TextInput };
