import { useMemo } from "react";
import { useWorkflowProviders } from "@/utils/hooks/useProviders";
import {
  getYamlWorkflowDefinitionSchema,
  YamlWorkflowDefinitionSchema,
} from "../model/yaml.schema";

export function useWorkflowZodSchema() {
  const { data: { providers } = {} } = useWorkflowProviders();
  return useMemo(() => {
    if (!providers) {
      return YamlWorkflowDefinitionSchema;
    }
    return getYamlWorkflowDefinitionSchema(providers);
  }, [providers]);
}
