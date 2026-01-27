"use client";
import dynamic from "next/dynamic";

export const WorkflowYAMLEditor = dynamic(
  () => import("./ui/WorkflowYAMLEditor").then((mod) => mod.WorkflowYAMLEditor),
  { ssr: false }
);
export type {
  WorkflowYAMLEditorDefaultProps,
  WorkflowYAMLEditorDiffProps,
  WorkflowYAMLEditorProps,
} from "./model/types";
export { isDiffEditorProps } from "./lib/utils";
