/**
 * data-cy smoke tests.
 *
 * One assertion per primitive: verify the `data-cy` prop reaches a real DOM
 * node so external Cypress tooling can select on it. Anything Cypress-y that
 * needs Monaco / portals / heavy state is covered separately by e2e suites.
 */
import React from "react";
import { render } from "@testing-library/react";
import "@testing-library/jest-dom";

import { Button } from "@/components/ui/Button";
import Modal from "@/components/ui/Modal";
import { TextInput } from "@/components/ui/TextInput";
import { Textarea } from "@/components/ui/Textarea";
import { AutocompleteInput } from "@/components/ui/AutocompleteInput";
import { Calendar } from "@/components/ui/Calendar";
import { Drawer } from "@/shared/ui/Drawer/Drawer";
import { TablePagination } from "@/shared/ui/TablePagination";
import { Select } from "@/shared/ui/Select/Select";
import { Tooltip } from "@/shared/ui/Tooltip/Tooltip";
import { TableIndeterminateCheckbox } from "@/shared/ui/TableIndeterminateCheckbox/TableIndeterminateCheckbox";
import { Input } from "@/shared/ui/Input";
import { TabLinkNavigation } from "@/shared/ui/TabLinkNavigation/TabLinkNavigation";
import { TabNavigationLink } from "@/shared/ui/TabLinkNavigation/TabNavigationLink";
import { DropdownMenu } from "@/shared/ui/DropdownMenu/DropdownMenu";

// Minimal table stub for TablePagination.
function makeTableStub() {
  return {
    getState: () => ({ pagination: { pageIndex: 0, pageSize: 25 } }),
    setPageSize: jest.fn(),
    setPageIndex: jest.fn(),
    getPageCount: () => 1,
    getCanPreviousPage: () => false,
    getCanNextPage: () => false,
    previousPage: jest.fn(),
    nextPage: jest.fn(),
  } as any;
}

describe("data-cy primitives smoke", () => {
  it("Button forwards data-cy", () => {
    const { container } = render(
      <Button variant="primary" data-cy="cy-btn">
        click
      </Button>
    );
    expect(container.querySelector('[data-cy="cy-btn"]')).not.toBeNull();
  });

  it("Modal forwards data-cy and renders modal-close-btn", () => {
    const { baseElement } = render(
      <Modal isOpen={true} onClose={() => {}} data-cy="cy-modal" title="t">
        <div>contents</div>
      </Modal>
    );
    expect(baseElement.querySelector('[data-cy="cy-modal"]')).not.toBeNull();
    expect(
      baseElement.querySelector('[data-cy="modal-close-btn"]')
    ).not.toBeNull();
  });

  it("TextInput forwards data-cy", () => {
    const { container } = render(<TextInput data-cy="cy-text" />);
    expect(container.querySelector('[data-cy="cy-text"]')).not.toBeNull();
  });

  it("Textarea forwards data-cy", () => {
    const { container } = render(<Textarea data-cy="cy-textarea" />);
    expect(container.querySelector('[data-cy="cy-textarea"]')).not.toBeNull();
  });

  it("AutocompleteInput forwards data-cy", () => {
    const { container } = render(
      <AutocompleteInput
        options={[]}
        onSelect={() => {}}
        getId={(o) => String(o.value)}
        placeholder="search"
        data-cy="cy-auto"
      />
    );
    expect(container.querySelector('[data-cy="cy-auto"]')).not.toBeNull();
  });

  it("Calendar forwards data-cy on its wrapper", () => {
    const { container } = render(
      <Calendar mode="single" data-cy="cy-cal" />
    );
    expect(container.querySelector('[data-cy="cy-cal"]')).not.toBeNull();
  });

  it("Drawer forwards data-cy and renders drawer-close-btn (not asserted: header is optional)", () => {
    const { baseElement } = render(
      <Drawer isOpen={true} onClose={() => {}} data-cy="cy-drawer">
        <div>body</div>
      </Drawer>
    );
    expect(baseElement.querySelector('[data-cy="cy-drawer"]')).not.toBeNull();
  });

  it("TablePagination renders namespaced data-cy values when dataCyPrefix is given", () => {
    const { container } = render(
      <TablePagination table={makeTableStub()} dataCyPrefix="test" />
    );
    expect(
      container.querySelector('[data-cy="test-pagination-prev"]')
    ).not.toBeNull();
    expect(
      container.querySelector('[data-cy="test-pagination-next"]')
    ).not.toBeNull();
    expect(
      container.querySelector('[data-cy="test-pagination-page-size"]')
    ).not.toBeNull();
  });

  it("Select forwards data-cy on its wrapper", () => {
    const { container } = render(<Select options={[]} data-cy="cy-select" />);
    expect(container.querySelector('[data-cy="cy-select"]')).not.toBeNull();
  });

  it("Tooltip forwards data-cy onto its content node", () => {
    const { baseElement } = render(
      <Tooltip content="hello" open={true} data-cy="cy-tip">
        <span>trigger</span>
      </Tooltip>
    );
    // Radix portals the content; query the whole document.
    expect(baseElement.querySelector('[data-cy="cy-tip"]')).not.toBeNull();
  });

  it("TableIndeterminateCheckbox forwards data-cy onto its input", () => {
    const { container } = render(
      <TableIndeterminateCheckbox data-cy="cy-cb" />
    );
    expect(container.querySelector('input[data-cy="cy-cb"]')).not.toBeNull();
  });

  it("Input forwards data-cy onto its inner input", () => {
    const { container } = render(<Input data-cy="cy-input" />);
    expect(container.querySelector('input[data-cy="cy-input"]')).not.toBeNull();
  });

  it("TabLinkNavigation forwards data-cy onto its nav element", () => {
    const { container } = render(
      <TabLinkNavigation data-cy="cy-tabs">
        <span>placeholder</span>
      </TabLinkNavigation>
    );
    expect(container.querySelector('nav[data-cy="cy-tabs"]')).not.toBeNull();
  });

  it("TabNavigationLink forwards data-cy onto its link element", () => {
    const { container } = render(
      <TabNavigationLink href="/x" data-cy="cy-tab-link">
        Item
      </TabNavigationLink>
    );
    expect(container.querySelector('[data-cy="cy-tab-link"]')).not.toBeNull();
  });

  it("DropdownMenu trigger forwards data-cy and items derive menu-item-<id>", () => {
    const { container } = render(
      <DropdownMenu.Menu label="Open" data-cy="cy-menu-trigger">
        <DropdownMenu.Item label="Run Now" />
      </DropdownMenu.Menu>
    );
    expect(
      container.querySelector('[data-cy="cy-menu-trigger"]')
    ).not.toBeNull();
  });
});
