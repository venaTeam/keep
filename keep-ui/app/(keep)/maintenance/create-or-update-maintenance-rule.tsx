import {
  TextInput,
  Textarea,
  Divider,
  Subtitle,
  Text,
  Button,
  Switch,
  NumberInput,
  Select,
  SelectItem,
  MultiSelect,
  MultiSelectItem,
} from "@tremor/react";
import { FormEvent, useEffect, useState } from "react";
import { toast } from "react-toastify";
import { MaintenanceRule } from "./model";
import { useMaintenanceRules } from "utils/hooks/useMaintenanceRules";
import { AlertsRulesBuilder } from "@/features/presets/presets-manager";
import DatePicker from "react-datepicker";
import "react-datepicker/dist/react-datepicker.css";
import { useRouter } from "next/navigation";
import { useApi } from "@/shared/lib/hooks/useApi";
import { showErrorToast } from "@/shared/ui";
import { Status } from "@/entities/alerts/model";
import { capitalize } from "@/utils/helpers";

interface Props {
  maintenanceToEdit: MaintenanceRule | null;
  editCallback: (rule: MaintenanceRule | null) => void;
}

const DEFAULT_IGNORE_STATUSES = [
  "resolved",
  "acknowledged",
]

const roundTime = (dateToRound: Date) => {
  if (dateToRound.getMinutes() % 15 != 0) {
    const minToadd = 15 - (dateToRound.getMinutes() % 15);
    dateToRound.setMinutes(dateToRound.getMinutes() + minToadd);
    dateToRound.setSeconds(0);
    dateToRound.setMilliseconds(0);
  }
  return dateToRound;
}


export default function CreateOrUpdateMaintenanceRule({
  maintenanceToEdit,
  editCallback,
}: Props) {
  const api = useApi();
  const { mutate } = useMaintenanceRules();
  const [maintenanceName, setMaintenanceName] = useState<string>(maintenanceToEdit?.name ?? "");
  const [description, setDescription] = useState<string>(maintenanceToEdit?.description ?? "");
  const [celQuery, setCelQuery] = useState<string>(maintenanceToEdit?.cel_query ?? "");
  const [startTime, setStartTime] = useState<Date | null>(
    maintenanceToEdit
      ? new Date(new Date(maintenanceToEdit.start_time + 'Z').toLocaleString("en-US", { timeZone: "Asia/Jerusalem" }))
      : roundTime(new Date())
  );
  const [endInterval, setEndInterval] = useState<number>(
    maintenanceToEdit?.duration_seconds ? maintenanceToEdit.duration_seconds / 60 : 5
  );
  const [intervalType, setIntervalType] = useState<string>("minutes");
  const [enabled, setEnabled] = useState<boolean>(maintenanceToEdit?.enabled ?? true);
  const [suppress, setSuppress] = useState<boolean>(maintenanceToEdit?.suppress ?? false);
  const [ignoreStatuses, setIgnoreStatuses] = useState<string[]>(maintenanceToEdit?.ignore_statuses ?? DEFAULT_IGNORE_STATUSES);
  const [formResetKey, setFormResetKey] = useState(0);
  const editMode = maintenanceToEdit !== null;
  const router = useRouter();
  useEffect(() => {
    if (maintenanceToEdit) {
      setMaintenanceName(maintenanceToEdit.name);
      setDescription(maintenanceToEdit.description ?? "");
      setCelQuery(maintenanceToEdit.cel_query);
      setStartTime(new Date(new Date(maintenanceToEdit.start_time + 'Z').toLocaleString("en-US", { timeZone: "Asia/Jerusalem" })));
      setSuppress(maintenanceToEdit.suppress);
      setEnabled(maintenanceToEdit.enabled);
      setIgnoreStatuses(maintenanceToEdit.ignore_statuses);
      if (maintenanceToEdit.duration_seconds) {
        setEndInterval(maintenanceToEdit.duration_seconds / 60);
      }
    }
  }, [maintenanceToEdit]);

  const clearForm = () => {
    setMaintenanceName("");
    setDescription("");
    setCelQuery("");
    setStartTime(roundTime(new Date()));
    setEndInterval(5);
    setSuppress(false);
    setEnabled(true);
    setIgnoreStatuses([]);
    setFormResetKey((k) => k + 1);
    router.replace("/maintenance");
  };

  const isSameDay = (date1: Date, date2: Date): boolean => {
    return date1.toDateString() === date2.toDateString();
  }

  const changeDatePicker = (date: Date): void => {
    const currentDate = new Date();
    if (startTime && !isSameDay(date, startTime)) {
      if (isSameDay(date, currentDate) &&
        (date.getHours() < currentDate.getHours() || (date.getHours() == currentDate.getHours() && date.getMinutes() < currentDate.getMinutes()))) {
        setStartTime(roundTime(currentDate));
      }
      else {
        date?.setHours(startTime.getHours())
        date?.setMinutes(startTime.getMinutes())
        setStartTime(date);
      }
    }
    else setStartTime(roundTime(date));
  }

  const calculateDurationInSeconds = () => {
    let durationInSeconds = 0;
    switch (intervalType) {
      case "seconds":
        durationInSeconds = endInterval;
        break;
      case "minutes":
        durationInSeconds = endInterval * 60;
        break;
      case "hours":
        durationInSeconds = endInterval * 60 * 60;
        break;
      case "days":
        durationInSeconds = endInterval * 60 * 60 * 24;
        break;
      default:
        console.error("Invalid interval type");
    }
    return durationInSeconds;
  };

  const addMaintenanceRule = async (e: FormEvent) => {
    e.preventDefault();
    try {
      const response = await api.post("/maintenance", {
        name: maintenanceName,
        description: description,
        cel_query: celQuery,
        start_time: startTime?.toISOString(),
        duration_seconds: calculateDurationInSeconds(),
        suppress: suppress,
        enabled: enabled,
        ignore_statuses: ignoreStatuses,
      });
      clearForm();
      mutate();
      toast.success("Maintenance rule created successfully");
    } catch (error) {
      showErrorToast(error, "Failed to create maintenance rule");
    }
  };

  const updateMaintenanceRule = async (e: FormEvent) => {
    e.preventDefault();
    if (!maintenanceToEdit?.id) {
      showErrorToast(new Error("No maintenance rule selected for update"));
      return;
    }
    try {
      const response = await api.put(`/maintenance/${maintenanceToEdit.id}`, {
        name: maintenanceName,
        description: description,
        cel_query: celQuery,
        start_time: startTime?.toISOString(),
        duration_seconds: calculateDurationInSeconds(),
        suppress: suppress,
        enabled: enabled,
        ignore_statuses: ignoreStatuses,
      });
      exitEditMode();
      clearForm();
      mutate();
      toast.success("Maintenance rule updated successfully");
    } catch (error) {
      showErrorToast(error, "Failed to update maintenance rule");
    }
  };

  const exitEditMode = () => {
    editCallback(null);
    clearForm();
  };

  // Ensure CEL is a proper filter expression with field references on the left side
  const isCelFilterExpression = (cel: string): boolean => {
    if (!cel.trim()) return false;
    // Must contain at least one comparison operator or filter function
    const hasOperator = /[=!<>]=?|\.contains\s*\(|\.startsWith\s*\(|\.endsWith\s*\(|\.matches\s*\(|\bin\b|\.has\s*\(/.test(cel);
    if (!hasOperator) return false;

    // Check that left operands are field identifiers, not literals
    const parts = cel.split(/\s*(?:&&|\|\|)\s*/);
    for (const part of parts) {
      // Strip leading whitespace, parentheses, and negation
      const trimmed = part.replace(/^[\s(!]+/, "");
      if (!trimmed) continue;
      // Reject if left side starts with a string literal, number, or boolean/null
      if (/^["']/.test(trimmed) || /^\d/.test(trimmed) || /^(true|false|null)\b/.test(trimmed)) {
        return false;
      }
    }
    return true;
  };

  const submitEnabled = (): boolean => {
    return !!maintenanceName && isCelFilterExpression(celQuery) && !!startTime;
  };

  return (
    <form
      className="py-2"
      onSubmit={editMode ? updateMaintenanceRule : addMaintenanceRule}
    >
      <Subtitle>Maintenance Rule Metadata</Subtitle>
      <div className="mt-2.5">
        <Text>
          Name<span className="text-red-500 text-xs">*</span>
        </Text>
        <TextInput
          placeholder="Maintenance Name"
          required={true}
          value={maintenanceName}
          onValueChange={setMaintenanceName}
        />
      </div>
      <div className="mt-2.5">
        <Text>Description</Text>
        <Textarea
          placeholder="Maintenance Description"
          value={description}
          onValueChange={setDescription}
        />
      </div>
      <div className="mt-2.5">
        <AlertsRulesBuilder
          key={`${maintenanceToEdit?.id ?? "new"}-${formResetKey}`}
          defaultQuery=""
          celValue={celQuery}
          updateOutputCEL={setCelQuery}
          showSave={false}
          showSqlImport={false}
          applyOnTyping={true}
          shouldSetQueryParam={false}
        />
        {celQuery && !isCelFilterExpression(celQuery) && (
          <div className="text-red-500 text-sm mt-1">
            CEL expression must be a filter (e.g. name == &quot;test&quot;, severity &gt; &quot;info&quot;, source.contains(&quot;grafana&quot;)).
          </div>
        )}
      </div>

      <div className="mt-2.5">
        <MultiSelect value={ignoreStatuses} onValueChange={setIgnoreStatuses}>
          {Object.values(Status).map((value) => {
            return <MultiSelectItem key={value} value={value}>{capitalize(value)}</MultiSelectItem>
          })}
        </MultiSelect>
      </div>
      <div className="mt-2.5">
        <Text>
          Start At<span className="text-red-500 text-xs">*</span>
        </Text>
        <DatePicker
          onChange={changeDatePicker}
          showTimeSelect
          selected={startTime}
          timeFormat="p"
          timeIntervals={15}
          minDate={new Date()}
          minTime={startTime?.toDateString() == new Date().toDateString() ? new Date() : undefined}
          maxTime={startTime?.toDateString() == new Date().toDateString() ? new Date(new Date().setHours(23, 59, 59, 999)) : undefined}
          timeCaption="Time"
          dateFormat="MMMM d, yyyy h:mm:ss aa"
          inline
        />
      </div>
      <div className="mt-2.5">
        <Text>
          End After<span className="text-red-500 text-xs">*</span>
        </Text>
        <div className="flex gap-2">
          <NumberInput
            value={endInterval}
            onValueChange={setEndInterval}
            min={1}
          />
          <Select value={intervalType} onValueChange={setIntervalType}>
            <SelectItem value="minutes">Minutes</SelectItem>
            <SelectItem value="hours">Hours</SelectItem>
            <SelectItem value="days">Days</SelectItem>
          </Select>
        </div>
        <Text className="text-xs text-red-400">
          * Please adjust when editing existing maintenance rule, as this is
          calculated upon submit.
        </Text>
      </div>
      <div className="flex items-center space-x-3 mt-2.5 w-[300px] justify-between">
        <label
          htmlFor="ignoreSwitch"
          className="whitespace-nowrap text-tremor-default text-tremor-content dark:text-dark-tremor-content"
        >
          Alerts Display Mode
        </label>
        <Select value={(suppress ? "true" : "false")} onValueChange={(value) => setSuppress(value === "true")}>
          <SelectItem value="true">Show in Suppressed Status</SelectItem>
          <SelectItem value="false">Hide From Feed</SelectItem>
        </Select>
      </div>
      <div className="flex items-center space-x-3 w-[300px] justify-between mt-2.5">
        <label
          htmlFor="enabledSwitch"
          className="text-tremor-default text-tremor-content dark:text-dark-tremor-content"
        >
          Enable Rule
        </label>
        <Switch id="enabledSwitch" checked={enabled} onChange={setEnabled} />
      </div>
      <Divider />
      <div className={"space-x-1 flex flex-row justify-end items-center"}>
        {editMode ? (
          <Button
            color="orange"
            size="xs"
            variant="secondary"
            onClick={exitEditMode}
          >
            Cancel
          </Button>
        ) : null}
        <Button
          disabled={!submitEnabled()}
          color="orange"
          size="xs"
          type="submit"
        >
          {editMode ? "Update" : "Create"}
        </Button>
      </div>
    </form>
  );
}
