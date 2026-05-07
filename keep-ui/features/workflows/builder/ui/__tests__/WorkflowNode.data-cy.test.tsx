import React from "react";
import { render } from "@testing-library/react";
import "@testing-library/jest-dom";
import { ReactFlowProvider } from "@xyflow/react";
import WorkflowNode from "../WorkflowNode";

// Mocks: avoid pulling the entire workflow store / Image / config networking.
jest.mock("@/entities/workflows", () => ({
  useWorkflowStore: () => ({
    selectedNode: null,
    setSelectedNode: jest.fn(),
    isEditorSyncedWithNodes: true,
    validationErrors: {},
    deleteNodes: jest.fn(),
  }),
}));

jest.mock("@/utils/hooks/useConfig", () => ({
  useConfig: () => ({ data: { KEEP_WORKFLOW_DEBUG: false } }),
}));

jest.mock("next/image", () => ({
  __esModule: true,
  default: (props: any) => <img {...props} />,
}));

jest.mock("@/components/ui", () => ({
  DynamicImageProviderIcon: (props: any) => <img alt="provider" {...props} />,
}));

describe("WorkflowNode data-cy propagation", () => {
  it("forwards a wf-node-<componentType>-<id> selector onto the inner DOM root", () => {
    const data: any = {
      id: "step-http-1",
      name: "http call",
      type: "step-http",
      componentType: "task",
      properties: {},
      isLayouted: true,
    };
    const NodeAsAny = WorkflowNode as unknown as React.FC<{ id: string; data: typeof data }>;
    const { container } = render(
      <ReactFlowProvider>
        <NodeAsAny id="step-http-1" data={data} />
      </ReactFlowProvider>
    );
    expect(
      container.querySelector('[data-cy="wf-node-task-step-http-1"]')
    ).not.toBeNull();
  });
});
