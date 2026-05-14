"use client";
import { useParams } from "next/navigation";
import { ChangeEvent, useEffect, useState } from "react";
import GridLayout from "../GridLayout";
import WidgetModal from "../WidgetModal";
import { Button, Card, Icon, Subtitle, TextInput } from "@tremor/react";
import {
  GenericsMetrics,
  LayoutItem,
  Threshold,
  WidgetData,
  WidgetType,
} from "../types";
import { FiEdit2, FiSave } from "react-icons/fi";
import { useDashboards } from "utils/hooks/useDashboards";
import { toast } from "react-toastify";
import { GenericFilters } from "@/components/filters/GenericFilters";
import { useDashboardPreset } from "utils/hooks/useDashboardPresets";
import {
  MetricsWidget,
  useDashboardMetricWidgets,
} from "@/utils/hooks/useDashboardMetricWidgets";
import { useApi } from "@/shared/lib/hooks/useApi";
import { showErrorToast } from "@/shared/ui";
import "../styles.css";
import { Preset } from "@/entities/presets/model/types";
import { recordAction, recordPageLoad, recordError } from "@/utils/metrics";

const DASHBOARD_FILTERS = [
  {
    type: "date",
    key: "time_stamp",
    value: "",
    name: "Last received",
  },
];

const DashboardPage = () => {

  // Record page load time - call directly since useEffect may not fire reliably in Next.js React 19
  if (typeof window !== "undefined") {
    recordPageLoad("dashboard_detail", 0);
  }
  const api = useApi();
  const allPresets = useDashboardPreset();
  const { id }: any = useParams();
  const { dashboards, isLoading, mutate: mutateDashboard } = useDashboards();
  const [isModalOpen, setIsModalOpen] = useState(false);
  const [layout, setLayout] = useState<LayoutItem[]>([]);
  const [widgetData, setWidgetData] = useState<WidgetData[]>([]);
  const { widgets: allMetricWidgets } = useDashboardMetricWidgets(true);
  const [editingItem, setEditingItem] = useState<WidgetData | null>(null);
  const [dashboardName, setDashboardName] = useState(decodeURIComponent(id));
  const [isEditingName, setIsEditingName] = useState(false);

  useEffect(() => {
    if (!isLoading) {
      const dashboard = dashboards?.find(
        (d) => d.dashboard_name === decodeURIComponent(id)
      );
      if (dashboard) {
        setLayout(dashboard.dashboard_config.layout);
        setWidgetData(dashboard.dashboard_config.widget_data);
        setDashboardName(dashboard.dashboard_name);
      }
    }
  }, [id, dashboards, isLoading]);

  const openModal = () => {
    setEditingItem(null); // Ensure new modal opens without editing item context
    setIsModalOpen(true);
  };
  const closeModal = () => setIsModalOpen(false);

  const handleAddWidget = (widget: any) => {
    const uniqueId = `w-${Date.now()}`;
    const newItem: LayoutItem = {
      i: uniqueId,
      x: 0,
      y: 0,
      w: 3,
      h: 3,
      minW: 2,
      minH: 3,
      static: false,
    };
    const newWidget: WidgetData = {
      ...newItem,
      ...widget,
    };
    setLayout((prevLayout) => [...prevLayout, newWidget]);
    setWidgetData((prevData) => [...prevData, newWidget]);
  };

  const handleEditWidget = (id: string, update?: WidgetData) => {
    let itemToEdit = widgetData.find((d) => d.i === id) || null;
    if (itemToEdit && update) {
      setEditingItem({ ...itemToEdit, ...update });
    } else {
      setEditingItem(itemToEdit);
    }
    setIsModalOpen(true);
  };

  const handleSaveEdit = (updatedItem: WidgetData) => {
    setWidgetData((prevData) =>
      prevData.map((item) => (item.i === updatedItem.i ? updatedItem : item))
    );
    closeModal();
  };

  const handleDeleteWidget = (id: string) => {
    setLayout(layout.filter((item) => item.i !== id));
    setWidgetData(widgetData.filter((item) => item.i !== id));
  };

  const handleLayoutChange = (newLayout: LayoutItem[]) => {
    setLayout(newLayout);
    setWidgetData((prevData) =>
      prevData.map((item) => {
        const newItem = newLayout.find((l) => l.i === item.i);
        return newItem ? { ...item, ...newItem } : item;
      })
    );
  };

  const handleSaveDashboard = async () => {
    try {
      let dashboard = dashboards?.find(
        (d) => d.dashboard_name === decodeURIComponent(id)
      );

      const method = dashboard ? "PUT" : "POST";
      const endpoint = `/dashboard${
        dashboard ? `/${encodeURIComponent(dashboard.id)}` : ""
      }`;

      const isNewDashboard = method === "POST";
      const start = isNewDashboard ? performance.now() : 0;

      const result = await api.post(
        endpoint,
        {
          dashboard_name: dashboardName,
          dashboard_config: {
            layout,
            widget_data: widgetData,
          },
        },
        {
          method,
        }
      );

      if (isNewDashboard) {
        recordAction("create_dashboard", (performance.now() - start) / 1000);
      }

      console.log("Dashboard saved successfully", result);
      mutateDashboard();
      toast.success("Dashboard saved successfully");
    } catch (error) {
      recordError("create_dashboard");
      showErrorToast(error, "Failed to save dashboard");
    }
  };

  const toggleEditingName = () => {
    setIsEditingName(!isEditingName);
  };

  const handleNameChange = (e: ChangeEvent<HTMLInputElement>) => {
    setDashboardName(e.target.value);
  };

  return (
    <div className="flex flex-col h-full">
      <div className="flex items-center justify-between mb-4">
        <div className="relative">
          {isEditingName ? (
            <TextInput
              value={dashboardName}
              onChange={handleNameChange}
              onBlur={toggleEditingName}
              placeholder="Dashboard Name"
              className="border-orange-500 focus:border-orange-600 focus:ring-orange-600"
            />
          ) : (
            <Subtitle color="orange" className="mr-2">
              {dashboardName}
            </Subtitle>
          )}
          <Icon
            size="xs"
            icon={FiEdit2}
            onClick={toggleEditingName}
            className="cursor-pointer absolute right-0 top-0 transform -translate-y-1/2 translate-x-1/2 text-sm"
            color="orange"
          />
        </div>
        <div className="flex gap-1 items-end">
          <GenericFilters filters={DASHBOARD_FILTERS} />
          <div className="flex">
            <Button
              icon={FiSave}
              color="orange"
              size="sm"
              onClick={handleSaveDashboard}
              tooltip="Save current dashboard"
            />
            <Button color="orange" onClick={openModal} className="ml-2">
              Add Widget
            </Button>
          </div>
        </div>
      </div>
      {layout.length === 0 ? (
        <Card
          className="w-full h-full flex items-center justify-center cursor-pointer"
          onClick={openModal}
        >
          <div className="text-center">
            <p className="text-lg font-medium">No widgets available</p>
            <p className="text-gray-500">Click to add your first widget</p>
          </div>
        </Card>
      ) : (
        <Card className="w-full h-full">
          <GridLayout
            layout={layout}
            onLayoutChange={handleLayoutChange}
            data={widgetData}
            onEdit={handleEditWidget}
            onDelete={handleDeleteWidget}
            onSave={handleSaveEdit}
            presets={allPresets}
            metrics={allMetricWidgets}
          />
        </Card>
      )}
      {isModalOpen && (
        <WidgetModal
          isOpen={true}
          onClose={closeModal}
          onAddWidget={handleAddWidget}
          onEditWidget={handleSaveEdit}
          presets={allPresets}
          editingItem={editingItem}
          metricWidgets={allMetricWidgets}
        />
      )}
    </div>
  );
};

export default DashboardPage;
