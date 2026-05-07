"use client";

import { TableBody, TableCell, TableRow } from "@tremor/react";
import type { Table as ReactTable } from "@tanstack/react-table";
import { AlertDto } from "@/entities/alerts/model";
import { getCommonPinningStylesAndClassNames } from "@/shared/ui";
import Skeleton from "react-loading-skeleton";
import "react-loading-skeleton/dist/skeleton.css";

export function IncidentAlertsTableBodySkeleton({
  table,
  pageSize,
}: {
  table: ReactTable<AlertDto>;
  pageSize: number;
}) {
  return (
    <TableBody data-cy="incidents-alerts-table-body-skeleton">
      {Array(pageSize)
        .fill("")
        .map((_, index) => (
          <TableRow key={`row-${index}`} data-cy="incidents-alerts-skeleton-row">
            {table.getVisibleFlatColumns().map((column) => {
              const { style, className } = getCommonPinningStylesAndClassNames(
                column,
                table.getState().columnPinning.left?.length,
                table.getState().columnPinning.right?.length
              );
              return (
                <TableCell
                  key={`cell-${column.id}-${index}`}
                  className={className}
                  style={style}
                  data-cy={`incidents-alerts-skeleton-cell-${column.id}`}
                >
                  <Skeleton />
                </TableCell>
              );
            })}
          </TableRow>
        ))}
    </TableBody>
  );
}
