import React from "react";
import { createSelectable, TSelectableItemProps } from "react-selectable-fast";
import { TableRow } from "@tremor/react";
import clsx from "clsx";

interface Props {
    children: React.ReactNode;
    className?: string;
    onClick?: (e: React.MouseEvent) => void;
    onMouseDown?: (e: React.MouseEvent) => void;
    onMouseEnter?: () => void;
}

const Row = ({
    children,
    className,
    onClick,
    onMouseDown,
    onMouseEnter,
    selectableRef,
    isSelecting,
    isSelected,
}: Props & TSelectableItemProps) => {
    return (
        <TableRow
            ref={selectableRef}
            className={clsx(
                className,
                isSelecting && "!bg-blue-100/50",
                isSelected && "!bg-blue-200/50"
            )}
            onClick={onClick}
            onMouseDown={onMouseDown}
            onMouseEnter={onMouseEnter}
        >
            {children}
        </TableRow>
    );
};

export const SelectableRow = createSelectable(Row);
