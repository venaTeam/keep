import React from "react";
import { Button, Card, Title } from "@tremor/react";
import { ArrowPathIcon } from "@heroicons/react/24/outline";
import {
  CheckCircleIcon,
  BellIcon,
  BellSlashIcon,
  EyeIcon,
  UserIcon,
  ChatBubbleLeftIcon,
  ArrowPathRoundedSquareIcon,
} from "@heroicons/react/20/solid";
import { AlertDto, AuditEvent } from "@/entities/alerts/model";
import { getInitials } from "@/components/navbar/UserAvatar";
import { DynamicImageProviderIcon } from "@/components/ui";
import clsx from "clsx";

/**
 * Format timestamp into separate date and time components for better readability
 */
const formatTimestamp = (timestamp: Date | string) => {
  const date = timestamp.toString().endsWith("Z")
    ? new Date(timestamp)
    : new Date(timestamp.toString() + "Z");

  const now = new Date();
  const isCurrentYear = date.getFullYear() === now.getFullYear();

  return {
    date: date.toLocaleDateString(undefined, {
      month: "short",
      day: "numeric",
      ...(isCurrentYear ? {} : { year: "numeric" }),
    }),
    time: date.toLocaleTimeString(undefined, {
      hour: "2-digit",
      minute: "2-digit",
    }),
  };
};

/**
 * Parse audit description to separate the main description from any attached note
 */
const parseAuditDescription = (
  description: string
): { mainDescription: string; note: string | null } => {
  // Match patterns like "- With note: ..." or just "With note: ..."
  const noteMatch = description.match(/\s*-?\s*With note:\s*(.+)$/i);
  if (noteMatch) {
    return {
      mainDescription: description.replace(noteMatch[0], "").trim(),
      note: noteMatch[1].trim(),
    };
  }
  return { mainDescription: description, note: null };
};

/**
 * Get action-specific styling based on the action type
 */
const getActionConfig = (action: string) => {
  const actionLower = action.toLowerCase();

  if (actionLower.includes("resolved")) {
    return {
      icon: CheckCircleIcon,
      bgColor: "bg-green-100",
      iconColor: "text-green-600",
      borderColor: "border-green-200",
    };
  }
  if (actionLower.includes("acknowledged")) {
    return {
      icon: EyeIcon,
      bgColor: "bg-blue-100",
      iconColor: "text-blue-600",
      borderColor: "border-blue-200",
    };
  }
  if (actionLower.includes("suppressed")) {
    return {
      icon: BellSlashIcon,
      bgColor: "bg-gray-100",
      iconColor: "text-gray-600",
      borderColor: "border-gray-200",
    };
  }
  if (actionLower.includes("triggered") || actionLower.includes("firing")) {
    return {
      icon: BellIcon,
      bgColor: "bg-orange-100",
      iconColor: "text-orange-600",
      borderColor: "border-orange-200",
    };
  }
  if (actionLower.includes("assigned")) {
    return {
      icon: UserIcon,
      bgColor: "bg-purple-100",
      iconColor: "text-purple-600",
      borderColor: "border-purple-200",
    };
  }
  if (actionLower.includes("comment") || actionLower.includes("note")) {
    return {
      icon: ChatBubbleLeftIcon,
      bgColor: "bg-yellow-100",
      iconColor: "text-yellow-600",
      borderColor: "border-yellow-200",
    };
  }
  // Default for status changes and other actions
  return {
    icon: ArrowPathRoundedSquareIcon,
    bgColor: "bg-orange-50",
    iconColor: "text-orange-500",
    borderColor: "border-orange-200",
  };
};

type TimelineEntryProps = {
  entry: AuditEvent | { user_id: string; action: string; description: string; timestamp: Date | string };
  isLast: boolean;
};

const TimelineEntry: React.FC<TimelineEntryProps> = ({ entry, isLast }) => {
  const { date, time } = formatTimestamp(entry.timestamp);
  const { mainDescription, note } = parseAuditDescription(entry.description);
  const actionConfig = getActionConfig(entry.action);
  const ActionIcon = actionConfig.icon;
  const isSystem = entry.user_id.toLowerCase() === "system";

  return (
    <div className={clsx(
      "relative",
      !isLast && "pb-4 mb-4 border-b border-gray-100"
    )}>
      {/* Entry container with subtle background */}
      <div className="flex gap-3 p-3 bg-gray-50/50 rounded-lg border border-gray-100 hover:bg-gray-50 transition-colors">
        {/* Avatar/Icon */}
        <div className="relative z-10 flex-shrink-0">
          {isSystem ? (
            <DynamicImageProviderIcon
              src="/icons/keep-icon.png"
              alt="Keep Logo"
              width={40}
              height={40}
              providerType="keep"
              className="rounded-full border-2 border-white shadow-sm"
            />
          ) : (
            <span className="relative inline-flex items-center justify-center w-10 h-10 overflow-hidden bg-orange-400 rounded-full border-2 border-white shadow-sm">
              <span className="font-medium text-white text-xs">
                {getInitials(entry.user_id)}
              </span>
            </span>
          )}
        </div>

        {/* Content */}
        <div className="flex-grow min-w-0 pt-0.5">
          {/* Header row with action and timestamp */}
          <div className="flex items-start justify-between gap-2 mb-1">
            <div className="flex items-center gap-2 min-w-0">
              <span
                className={clsx(
                  "inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-xs font-medium",
                  actionConfig.bgColor,
                  actionConfig.iconColor
                )}
              >
                <ActionIcon className="w-3.5 h-3.5" />
                <span className="truncate">{entry.action}</span>
              </span>
            </div>
            <div className="flex-shrink-0 text-right">
              <div className="text-xs font-medium text-gray-700">{date}</div>
              <div className="text-xs text-gray-500">{time}</div>
            </div>
          </div>

          {/* Description */}
          <p className="text-sm text-gray-600 leading-relaxed break-words">
            {mainDescription}
          </p>

          {/* Note section - visually separated */}
          {note && (
            <div className="mt-2 p-2.5 bg-amber-50 border border-amber-200 rounded-md">
              <div className="flex items-start gap-2">
                <ChatBubbleLeftIcon className="w-4 h-4 text-amber-600 flex-shrink-0 mt-0.5" />
                <div className="min-w-0">
                  <span className="text-xs font-medium text-amber-700 block mb-0.5">
                    Note
                  </span>
                  <p className="text-sm text-amber-900 break-words">{note}</p>
                </div>
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};

type AlertTimelineProps = {
  alert: AlertDto | null;
  auditData: AuditEvent[];
  isLoading: boolean;
  onRefresh: () => void;
};

export const AlertTimeline: React.FC<AlertTimelineProps> = ({
  alert,
  auditData,
  isLoading,
  onRefresh,
}) => {
  // Default audit event if no audit data is available
  const defaultAuditEvent = alert
    ? [
      {
        user_id: "system",
        action: "Alert triggered",
        description: "Alert received from provider with status firing",
        timestamp: alert.lastReceived,
      },
    ]
    : [];

  const auditContent = auditData?.length ? auditData : defaultAuditEvent;

  return (
    <div className="flex flex-col gap-3">
      <div className="flex justify-between items-center">
        <Title>Timeline</Title>
        <Button
          icon={ArrowPathIcon}
          color="orange"
          size="xs"
          variant="secondary"
          disabled={isLoading}
          loading={isLoading}
          onClick={onRefresh}
          title="Refresh"
        />
      </div>
      <Card className="p-4">
        {isLoading ? (
          <div className="flex justify-center items-center py-8">
            <div className="flex items-center gap-2 text-gray-500">
              <ArrowPathIcon className="w-5 h-5 animate-spin" />
              <span>Loading timeline...</span>
            </div>
          </div>
        ) : auditContent.length === 0 ? (
          <div className="flex justify-center items-center py-8 text-gray-500">
            No timeline events available
          </div>
        ) : (
          <div className="max-h-[400px] overflow-y-auto pr-2 -mr-2">
            {auditContent.map((entry, index) => (
              <TimelineEntry
                key={`timeline-${index}`}
                entry={entry}
                isLast={index === auditContent.length - 1}
              />
            ))}
          </div>
        )}
      </Card>
    </div>
  );
};
