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
import React, { FormEvent, useEffect, useState } from "react";
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

const roundTime =(dateToRound: Date) =>{
  if (dateToRound.getMinutes() % 15 === 0) {
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
  const [maintenanceName, setMaintenanceName] = useState<string>("");
  const [description, setDescription] = useState<string>("");
  const [celQuery, setCelQuery] = useState<string>("");
  const [startTime, setStartTime] = useState<Date | null>(roundTime(new Date()));
  const [endInterval, setEndInterval] = useState<number>(5);
  const [intervalType, setIntervalType] = useState<string>("minutes");
  const [enabled, setEnabled] = useState<boolean>(true);
  const [suppress, setSuppress] = useState<boolean>(false);
  const [ignoreStatuses, setIgnoreStatuses] = useState<string[]>(DEFAULT_IGNORE_STATUSES);
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
    router.replace("/maintenance");
  };

  const isSameDay = (date1: Date, date2: Date) => {
    return date1.toDateString() === date2.toDateString();
  }

  const changeDatePicker = (date: Date):void => {
    const currentDate = new Date();
    if (!isSameDay(date, startTime)) {
      if(isSameDay(date, currentDate) && 
      (date.getHours() < currentDate.getHours() || (date.getHours() === currentDate.getHours() && date.getMinutes() < currentDate.getMinutes()))) {
        setStartTime(roundTime(currentDate));
      }
      else{
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

  const submitEnabled = (): boolean => {
    return !!maintenanceName && !!celQuery && !!startTime;
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
          defaultQuery={celQuery}
          updateOutputCEL={setCelQuery}
          showSave={false}
          showSqlImport={false}
        />
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
        <Select value={suppress ? "true" : "false" onValueChange={(value: string) => setSuppress(value === "true")}}>
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
