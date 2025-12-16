import { Button, Select, SelectItem, Subtitle, TextInput, Icon } from "@tremor/react";
import React, { useEffect, useMemo } from "react";
import { Controller, get, useFieldArray, useForm, useWatch } from "react-hook-form";
import { LayoutItem, Threshold } from "../../types";
import { Trashcan } from "@/components/icons";

interface ServiceNowForm {
  team?: string;
  status: "open" | "in_progress" | "both";
  detection: "direct" | "hamal" | "all";
  thresholds: Threshold[];
  customLink?: string;
}

export function ServiceNowWidgetForm({
  editingItem,
  onChange,
}: {
  editingItem?: any;
  onChange: (formState: any, isValid: boolean) => void;
}) {
  const {
    control,
    formState: { errors, isValid },
    register,
  } = useForm<ServiceNowForm>({
    defaultValues: {
      team: editingItem?.serviceNowTeam || "",
      status: editingItem?.serviceNowStatus || "both",
      detection: editingItem?.serviceNowDetection || "all",
      thresholds: editingItem?.thresholds || [
        { value: 0, color: "#10b981" },
        { value: 20, color: "#dc2626" },
      ],
      customLink: editingItem?.customLink || "",
    },
  });

  const { fields, append, remove, replace } = useFieldArray({
    control,
    name: "thresholds",
  });

  const formValues = useWatch({ control });

  const normalizedFormValues = useMemo(() => {
    return {
      team: formValues.team || "",
      status: formValues.status || "both",
      detection: formValues.detection || "all",
      thresholds:
        formValues.thresholds?.map((t) => ({
          ...t,
          value: parseInt((t.value as any)?.toString(), 10) || 0,
        })) || [],
      customLink: formValues.customLink || "",
    };
  }, [formValues]);

  function getLayoutValues(): LayoutItem {
    if (editingItem) {
      return {} as LayoutItem;
    }

    return {
      w: 4,
      h: 3,
      minW: 0,
      minH: 2,
      static: false,
    } as LayoutItem;
  }

  useEffect(() => {
    onChange(
      {
        ...getLayoutValues(),
        serviceNowTeam: normalizedFormValues.team,
        serviceNowStatus: normalizedFormValues.status,
        serviceNowDetection: normalizedFormValues.detection,
        thresholds: normalizedFormValues.thresholds,
        customLink: normalizedFormValues.customLink,
      },
      isValid
    );
  }, [normalizedFormValues, isValid]);

  const handleThresholdBlur = () => {
    const reordered = formValues?.thresholds
      ?.map((t) => ({
        ...t,
        value: parseInt((t.value as any)?.toString(), 10) || 0,
      }))
      .sort((a, b) => a.value - b.value);
    if (!reordered) return;
    replace(reordered as any);
  };

  const handleAddThreshold = () => {
    const maxThreshold = Math.max(
      ...(formValues.thresholds?.map((t) => t.value) as any),
      0
    );
    append({ value: maxThreshold + 10, color: "#000000" });
  };

  return (
    <>
      <div className="mb-4 mt-2">
        <Subtitle>Team</Subtitle>
        <Controller
          name="team"
          control={control}
          rules={{
            required: { value: true, message: "Team is required" },
          }}
          render={({ field }) => (
            <TextInput
              {...field}
              placeholder="Enter team"
              error={!!get(errors, "team.message")}
              errorMessage={get(errors, "team.message")}
            />
          )}
        />
      </div>

      <div className="mb-4 mt-2">
        <Subtitle>INC Status</Subtitle>
        <Controller
          name="status"
          control={control}
          rules={{ required: true }}
          render={({ field }) => (
            <Select {...field} placeholder="Select incident status">
              <SelectItem value="open">Open</SelectItem>
              <SelectItem value="in_progress">In Progress</SelectItem>
              <SelectItem value="both">Both</SelectItem>
            </Select>
          )}
        />
      </div>

      <div className="mb-4 mt-2">
        <Subtitle>Detection Method</Subtitle>
        <Controller
          name="detection"
          control={control}
          rules={{ required: true }}
        render={({ field }) => (
            <Select {...field} placeholder="Select detection method">
              <SelectItem value="direct">Direct</SelectItem>
              <SelectItem value="hamal">Hamal</SelectItem>
              <SelectItem value="all">All</SelectItem>
            </Select>
          )}
        />
      </div>

      <div className="mb-4 mt-2">
        <Subtitle>Custom Link (optional)</Subtitle>
        <Controller
          name="customLink"
          control={control}
          render={({ field }) => (
            <TextInput
              {...field}
              placeholder="https://example.com"
              type="url"
            />
          )}
        />
      </div>

      <div className="mb-4">
        <div className="flex items-center justify-between">
          <Subtitle>Thresholds</Subtitle>
          <Button
            color="orange"
            variant="secondary"
            type="button"
            onClick={handleAddThreshold}
          >
            +
          </Button>
        </div>
        <div className="mt-4">
          {fields.map((field, index) => (
            <div key={field.id} className="flex items-center space-x-2 mb-2">
              <TextInput
                {...register(`thresholds.${index}.value`, { required: true })}
                onBlur={handleThresholdBlur}
                placeholder="Threshold value"
                type="number"
                required
              />
              <input
                type="color"
                {...register(`thresholds.${index}.color`, { required: true })}
                className="w-10 h-10 p-1 border"
                required
              />
              {fields.length > 1 && (
                <button
                  type="button"
                  onClick={() => remove(index)}
                  className="p-2"
                >
                  <Icon color="orange" icon={Trashcan} className="h-5 w-5" />
                </button>
              )}
            </div>
          ))}
        </div>
      </div>
    </>
  );
}


