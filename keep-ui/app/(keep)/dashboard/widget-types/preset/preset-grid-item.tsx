import React, { useMemo } from "react";
import { WidgetData, WidgetType, PresetPanelType } from "../../types";
import { usePresetAlertsCount } from "@/features/presets/custom-preset-links";
import { useDashboardPreset } from "@/utils/hooks/useDashboardPresets";
import { Button, Icon } from "@tremor/react";
import * as Tooltip from "@radix-ui/react-tooltip";
import Skeleton from "react-loading-skeleton";
import "react-loading-skeleton/dist/skeleton.css";
import { useRouter, useParams } from "next/navigation";
import TimeAgo from "react-timeago";
import { useSearchParams } from "next/navigation";
import WidgetAlertsTable from "./widget-alerts-table";
import WidgetAlertCountPanel from "./widget-alert-count-panel";
import CelInput from "@/features/cel-input/cel-input";

interface GridItemProps {
  item: WidgetData;
}

const PresetGridItem: React.FC<GridItemProps> = ({ item }) => {
  const searchParams = useSearchParams();
  const timeRangeCel = useMemo(() => {
    const timeRangeSearchParam = searchParams.get("time_stamp");
    if (timeRangeSearchParam) {
      const parsedTimeRange = JSON.parse(timeRangeSearchParam);
      return `lastReceived >= "${parsedTimeRange.start}" && lastReceived <= "${parsedTimeRange.end}"`;
    }
    return "";
  }, [searchParams]);
  const presets = useDashboardPreset();
  const countOfLastAlerts = (item.preset as any).countOfLastAlerts;
  const preset = useMemo(
    () => presets.find((preset) => preset.id === item.preset?.id),
    [presets, item.preset?.id]
  );
  const presetCel = useMemo(
    () => preset?.options.find((option) => option.label === "CEL")?.value || "",
    [preset]
  );
  const filterCel = useMemo(
    () => [timeRangeCel, presetCel].filter(Boolean).join(" && "),
    [presetCel, timeRangeCel]
  );

  const {
    alerts,
    totalCount: presetAlertsCount,
    isLoading,
  } = usePresetAlertsCount(
    filterCel,
    false,
    countOfLastAlerts,
    0,
    10000 // refresh interval
  );
  const router = useRouter();
  const params = useParams();
  const dashboardId = params?.id as string | undefined;

  function handleGoToPresetClick() {
    const dashboardName = dashboardId ? decodeURIComponent(dashboardId) : "";
    const presetUrl = `/alerts/${preset?.name.toLowerCase()}`;
    if (dashboardName) {
      router.push(`${presetUrl}?fromDashboard=${encodeURIComponent(dashboardName)}&widgetName=${encodeURIComponent(item.name)}`);
    } else {
      router.push(presetUrl);
    }
  }

  const getColor = () => {
    let color = "#000000";
    if (
      item.widgetType === WidgetType.PRESET &&
      item.thresholds &&
      item.preset
    ) {
      for (let i = item.thresholds.length - 1; i >= 0; i--) {
        if (item.preset && presetAlertsCount >= item.thresholds[i].value) {
          color = item.thresholds[i].color;
          break;
        }
      }
    }

    return color;
  };

  function hexToRgb(hex: string, alpha: number = 1) {
    // Remove '#' if present
    hex = hex.replace(/^#/, "");

    // Handle shorthand form (#f44 → #ff4444)
    if (hex.length === 3) {
      hex = hex
        .split("")
        .map((c) => c + c)
        .join("");
    }

    const bigint = parseInt(hex, 16);
    const r = (bigint >> 16) & 255;
    const g = (bigint >> 8) & 255;
    const b = bigint & 255;

    return `rgb(${r}, ${g}, ${b}, ${alpha})`;
  }

  function renderCEL() {
    if (!presetCel) {
      return;
    }

    return (
      <div className="flex gap-1 items-center">
        <div>Preset CEL:</div>
        <Tooltip.Provider>
          <Tooltip.Root>
            <Tooltip.Trigger asChild>
              <CelInput value={presetCel} readOnly></CelInput>
            </Tooltip.Trigger>
            <Tooltip.Portal>
              <Tooltip.Content sideOffset={5}>
                <div className="bg-white invert-dark-mode border py-0.5 px-1 rounded-md text-orange-500">
                  {presetCel}
                </div>
                <Tooltip.Arrow />
              </Tooltip.Content>
            </Tooltip.Portal>
          </Tooltip.Root>
        </Tooltip.Provider>
      </div>
    );
  }

  function renderAlertsCountText() {
    const label = "Alerts count:";
    let state: string = "nothingToShow";

    if (countOfLastAlerts > 0) {
      if (presetAlertsCount <= countOfLastAlerts) {
        state = "allAlertsShown";
      } else {
        state = "someAlertsShown";
      }
    }

    return (
      <div className="flex gap-1 items-center">
        <div>{label}</div>
        <div
          className="flex items-center text-base font-bold"
          style={{ color: getColor() }}
        >
          {isLoading && (
            <Skeleton containerClassName="h-4 w-8 relative -top-0.5" />
          )}
          {!isLoading && (
            <>
              {state === "nothingToShow" && (
                <span>{presetAlertsCount} alerts</span>
              )}
              {state === "allAlertsShown" && (
                <span>showing {presetAlertsCount} alerts</span>
              )}
              {state === "someAlertsShown" && (
                <span>
                  showing {countOfLastAlerts} out of {presetAlertsCount}
                </span>
              )}

            </>
          )}
        </div>
      </div>
    );
  }

  const isAlertTable = item.presetPanelType === PresetPanelType.ALERT_TABLE || !item.presetPanelType;
  const isAlertCountPanel = item.presetPanelType === PresetPanelType.ALERT_COUNT_PANEL;

  return (
    <div className="flex flex-col overflow-y-auto gap-2" data-cy="dashboard-widget-preset">
      {isAlertTable && (
        <>
          <div className="flex gap-2">
            <div className="flex-1 min-w-0 overflow-hidden whitespace-nowrap">
              <div className="flex gap-1 items-center">
                <div>Preset name:</div>
                <div
                  className="truncate cursor-pointer hover:text-orange-500 transition-colors"
                  onClick={handleGoToPresetClick}
                >
                  {preset?.name}
                </div>
              </div>
              {/* {renderCEL()} */}
              {renderAlertsCountText()}
            </div>
            <div className="flex items-center">
              <Button
                color="orange"
                variant="secondary"
                size="xs"
                onClick={handleGoToPresetClick}
                data-cy="dashboard-widget-preset-go-to-btn"
              >
                Go to preset
              </Button>
            </div>
          </div>
          {countOfLastAlerts > 0 && (
            <WidgetAlertsTable
              presetName={preset?.name as string}
              alerts={isLoading ? undefined : alerts}
              columns={(item as any)?.presetColumns}
              background={isLoading ? undefined : hexToRgb(getColor(), 0.1)}
            />
          )}
        </>
      )}
      {isAlertCountPanel && (
        <WidgetAlertCountPanel
          presetName={preset?.name as string}
          showFiringOnly={item.showFiringOnly}
          background={isLoading ? undefined : hexToRgb(getColor(), 0.1)}
          thresholds={item.thresholds}
          customLink={item.customLink}
          dashboardName={dashboardId ? decodeURIComponent(dashboardId) : undefined}
          widgetName={item.name}
        />
      )}
    </div>
  );
};

export default PresetGridItem;