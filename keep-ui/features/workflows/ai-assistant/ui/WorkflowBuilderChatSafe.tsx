import { useConfig } from "@/utils/hooks/useConfig";
import Image from "next/image";
import { SparklesIcon } from "@heroicons/react/24/outline";
import { Text, Title } from "@tremor/react";
import { Link } from "@/components/ui";
import { DefinitionV2 } from "@/entities/workflows";
import {
  WorkflowBuilderChat,
  WorkflowBuilderChatProps,
} from "./WorkflowBuilderChat";
import BuilderChatPlaceholder from "./ai-workflow-placeholder.png";

type WorkflowBuilderChatSafeProps = Omit<
  WorkflowBuilderChatProps,
  "definition"
> & {
  definition: DefinitionV2 | null;
};

export function WorkflowBuilderChatSafe({
  definition,
  ...props
}: WorkflowBuilderChatSafeProps) {
  const { data: config } = useConfig();

  // If AI is not enabled, return null to collapse the chat section
  if (!config?.OPEN_AI_API_KEY_SET) {
    return null;
  }

  if (definition == null) {
    return null;
  }

  return <WorkflowBuilderChat definition={definition} {...props} />;
}
