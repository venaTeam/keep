import { Badge } from "@tremor/react";
type AlertsFoundBadgeProps = {
  totalAlertsFound: number;
  isLoading: boolean;
  role: "ruleCondition" | "correlationRuleConditions";
};

export const AlertsFoundBadge = ({
  totalAlertsFound,
  isLoading,
  role,
}: AlertsFoundBadgeProps) => {
  function renderFoundAlertsText() {
    if (role === "ruleCondition") {
      return (
        <>
          {totalAlertsFound} alert{totalAlertsFound > 1 ? "s" : ""} were found
          matching this condition
        </>
      );
    }

    return (
      <>
        {totalAlertsFound} alert{totalAlertsFound > 1 ? "s" : ""} were found
        matching correlation rule conditions
      </>
    );
  }

  function getNotFoundText() {
    if (role === "ruleCondition") {
      return "No alerts were found with this condition. Please try something else.";
    }

    return "No alerts were found with these correlation rule conditions. Please try something else.";
  }

  if (totalAlertsFound === 0) {
    return (
      <Badge className="mt-3 w-full" color="gray">
        {isLoading ? "Getting your alerts..." : getNotFoundText()}
      </Badge>
    );
  }

  return (
    <Badge className="mt-3 w-full" color="teal">
      {renderFoundAlertsText()}
    </Badge>
  );
}
