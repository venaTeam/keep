import { Text, TextareaProps, TextInputProps } from "@tremor/react";
import { Textarea, TextInput } from "@/components/ui";
import React from "react";

export function EditorField({
  name,
  value,
  asTextarea,
  ...rest
}: TextInputProps & { asTextarea?: boolean }) {
  if (name === "code") {
    return (
      <div data-cy={`wf-editor-field-${name}`}>
        <Text className="capitalize mb-1.5">{name}</Text>
        <Textarea
          id={name}
          placeholder={name}
          className="mb-2.5 min-h-[100px] text-xs font-mono"
          value={value || ""}
          {...(rest as TextareaProps)}
          data-cy={`wf-editor-${name}-input`}
        />
      </div>
    );
  }
  if (asTextarea) {
    return (
      <div data-cy={`wf-editor-field-${name}`}>
        <Text className="capitalize mb-1.5">{name}</Text>
        <Textarea
          id={name}
          placeholder={name}
          className="mb-2.5 min-h-[100px] text-xs"
          value={value || ""}
          {...(rest as TextareaProps)}
          data-cy={`wf-editor-${name}-input`}
        />
      </div>
    );
  }
  return (
    <div data-cy={`wf-editor-field-${name}`}>
      <Text className="capitalize mb-1.5">{name}</Text>
      <TextInput
        id={name}
        placeholder={name}
        className="mb-2.5"
        value={value || ""}
        {...rest}
        data-cy={`wf-editor-${name}-input`}
      />
    </div>
  );
}
