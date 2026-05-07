import React from "react";
import { Button as TremorButton, ButtonProps } from "@tremor/react";
import { cn } from "utils/helpers";

type ButtonVariantType = "destructive" | ButtonProps["variant"];

// `data-cy` is forwarded as a bracketed string key (not camelCase) so the
// prop round-trips identically to the DOM attribute on the underlying button.
export function Button({
  variant,
  className,
  "data-cy": dataCy,
  ...props
}: { variant: ButtonVariantType; "data-cy"?: string } & Omit<
  ButtonProps,
  "variant"
>) {
  let variantClasses = "";

  if (variant === "destructive") {
    variantClasses =
      "bg-red-500 hover:bg-red-600 text-white border-red-500 hover:border-red-600";
  }

  return (
    <TremorButton
      className={cn(variantClasses, className)}
      variant={variant !== "destructive" ? variant : undefined}
      data-cy={dataCy}
      {...props}
    />
  );
}
