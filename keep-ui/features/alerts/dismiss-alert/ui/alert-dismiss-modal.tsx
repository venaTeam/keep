import { useState, useEffect } from "react";
import {
  Button,
  Title,
  Subtitle,
  Card,
  Tab,
  TabGroup,
  TabList,
  TabPanel,
  TabPanels,
  Callout,
  Textarea,
} from "@tremor/react";
import Modal from "@/components/ui/Modal";
import DatePicker from "react-datepicker";
import "react-datepicker/dist/react-datepicker.css";
import { AlertDto, Status } from "@/entities/alerts/model";
import { set, isSameDay, isAfter } from "date-fns";
import { useAlerts } from "@/entities/alerts/model/useAlerts";
import { toast } from "react-toastify";
import { useApi } from "@/shared/lib/hooks/useApi";
import { Select, showErrorToast } from "@/shared/ui";
import { useRevalidateMultiple } from "@/shared/lib/state-utils";
import {
  CheckCircleIcon,
  ExclamationCircleIcon,
  PauseIcon,
  CircleStackIcon,
} from "@heroicons/react/24/outline";
import "./alert-dismiss-modal.css";

const statusIcons = {
  [Status.Firing]: <ExclamationCircleIcon className="w-5 h-5 text-red-500 mr-2" />,
  [Status.Resolved]: <CheckCircleIcon className="w-5 h-5 text-green-500 mr-2" />,
  [Status.Acknowledged]: <PauseIcon className="w-5 h-5 text-gray-500 mr-2" />,
  [Status.Suppressed]: <CircleStackIcon className="w-5 h-5 text-gray-500 mr-2" />,
  [Status.Pending]: <CircleStackIcon className="w-5 h-5 text-gray-500 mr-2" />,
};

interface Props {
  preset: string;
  alert: AlertDto[] | null | undefined;
  handleClose: () => void;
  onSuccess?: () => void;
}

export function AlertDismissModal({
  preset: presetName,
  alert: alerts,
  handleClose,
  onSuccess,
}: Props) {
  const [dismissComment, setDismissComment] = useState<string>("");
  const [selectedTab, setSelectedTab] = useState<number>(0);
  const [selectedDateTime, setSelectedDateTime] = useState<Date | null>(null);
  const [showError, setShowError] = useState<boolean>(false);
  const [isLoading, setIsLoading] = useState<boolean>(false);
  const [disposeOnNewAlert, setDisposeOnNewAlert] = useState<boolean>(true);
  const [selectedStatus, setSelectedStatus] = useState<Status | null>(null);
  const [commentError, setCommentError] = useState<boolean>(false);

  const isRestore = alerts?.every((a) => a.dismissed);
  const revalidateMultiple = useRevalidateMultiple();
  const presetsMutator = () => revalidateMultiple(["/preset"]);
  const { alertsMutator } = useAlerts();

  const api = useApi();
  // Ensuring that the useEffect hook is called consistently
  useEffect(() => {
    const now = new Date();
    const roundedMinutes = Math.ceil(now.getMinutes() / 15) * 15;
    const defaultTime = set(now, {
      minutes: roundedMinutes,
      seconds: 0,
      milliseconds: 0,
    });
    setSelectedDateTime(defaultTime);
  }, []);

  if (!alerts) return null;

  const isOpen = !!alerts;

  const handleTabChange = (index: number) => {
    setSelectedTab(index);
    if (index === 0) {
      setSelectedDateTime(null);
      setShowError(false);
    }
  };

  const handleDateTimeChange = (date: Date) => {
    setSelectedDateTime(date);
    setShowError(false);
  };

  const handleDismissChange = async () => {
    if (selectedTab === 1 && !selectedDateTime) {
      setShowError(true);
      return;
    }

    if (!isRestore && !dismissComment.trim()) {
      setCommentError(true);
      return;
    }

    setIsLoading(true);

    const dismissUntil =
      selectedTab === 0 ? null : selectedDateTime?.toISOString();

    const plainTextNote = dismissComment.trim();

    const enrichments: {
      dismissed: boolean;
      note: string;
      dismissUntil?: string;
      status?: Status | null;
    } = {
      dismissed: !alerts[0]?.dismissed,
      note: plainTextNote,
      ...(!isRestore && { dismissUntil: dismissUntil || "" }),
      ...(isRestore && selectedStatus && { status: selectedStatus }),
    };

    const requestData = {
      enrichments: enrichments,
      fingerprints: alerts.map((alert: AlertDto) => alert.fingerprint),
    };

    try {
      const endpoint = isRestore
        ? "/alerts/batch_enrich?dispose_on_new_alert=false"
        : `/alerts/batch_enrich?dispose_on_new_alert=${disposeOnNewAlert}`;

      await api.post(endpoint, requestData);
      toast.success(
        `${alerts.length} alerts ${isRestore ? "restored" : "dismissed"
        } successfully!`,
        {
          position: "top-right",
        }
      );
      onSuccess?.();
      await alertsMutator();
      await presetsMutator();
    } catch (error) {
      showErrorToast(error, "Failed to dismiss alerts");
    } finally {
      clearAndClose();
      setIsLoading(false);
    }
  };

  const clearAndClose = () => {
    setSelectedTab(0);
    setSelectedDateTime(null);
    setDismissComment("");
    setShowError(false);
    setCommentError(false);
    setDisposeOnNewAlert(true);
    setSelectedStatus(null);
    handleClose();
  };

  const filterPassedTime = (time: Date) => {
    const currentDate = new Date();
    const selectedDate = new Date(time);

    if (isSameDay(currentDate, selectedDate)) {
      return isAfter(selectedDate, currentDate);
    }

    return true;
  };

  return (
    <Modal
      onClose={clearAndClose}
      isOpen={isOpen}
      className="overflow-visible"
      beforeTitle={alerts?.[0]?.name}
      title={isRestore ? "Restore Alert(s)" : "Dismiss Alert(s)"}
    >
      {isRestore ? (
        <>
          <Callout color="orange" title="Restoring Alerts" className="mb-2.5">
            This will restore the alert(s) and set their status.
          </Callout>
          <div className="flex mt-2.5 items-center mb-4">
            <Subtitle className="flex items-center font-bold mr-2">
              New status:
            </Subtitle>
            <Select
              options={Object.values(Status).map((status) => ({
                value: status,
                label: (
                  <div className="flex items-center">
                    {statusIcons[status]}
                    <span>{status.charAt(0).toUpperCase() + status.slice(1)}</span>
                  </div>
                ),
              }))}
              value={
                selectedStatus
                  ? {
                    value: selectedStatus,
                    label: (
                      <div className="flex items-center">
                        {statusIcons[selectedStatus]}
                        <span>
                          {selectedStatus.charAt(0).toUpperCase() +
                            selectedStatus.slice(1)}
                        </span>
                      </div>
                    ),
                  }
                  : null
              }
              onChange={(option) => setSelectedStatus(option?.value || null)}
              placeholder="Select new status"
              className="w-56"
            />
          </div>
          <Title>Restore Note</Title>
          <div className="mt-4">
            <Textarea
              value={dismissComment}
              onChange={(e) => setDismissComment(e.target.value)}
              placeholder="Add your restore note here..."
              rows={4}
            />
          </div>
          <div className="flex justify-end mt-4 space-x-2">
            <Button variant="secondary" color="orange" onClick={clearAndClose}>
              Cancel
            </Button>
            <Button
              onClick={handleDismissChange}
              color="orange"
              loading={isLoading}
            >
              Restore
            </Button>
          </div>
        </>
      ) : (
        <>
          <Callout color="orange" title="Dismissing Alerts" className="mb-2.5">
            {`This will dismiss the alert until an alert with the same fingerprint comes in${selectedTab === 1 ? ` or until ${selectedDateTime}.` : "."
              }`}
          </Callout>
          <div className="flex justify-end mb-4">
            <Button
              variant={disposeOnNewAlert ? "primary" : "secondary"}
              size="xs"
              onClick={() => setDisposeOnNewAlert(!disposeOnNewAlert)}
              tooltip={disposeOnNewAlert ? "Dispose the dismissal when a new alert comes in." : "Keep the dismissal when a new alert comes in."}
            >
              {disposeOnNewAlert ? "Disposing on new alerts" : "Keeping on new alerts"}
            </Button>
          </div>
          <TabGroup
            index={selectedTab}
            onIndexChange={(index: number) => handleTabChange(index)}
            className="mb-4"
          >
            <TabList>
              <Tab>Dismiss Forever</Tab>
              <Tab>Dismiss Until</Tab>
            </TabList>
            <TabPanels>
              <TabPanel></TabPanel>
              <TabPanel>
                <Card className="relative z-50 mt-4 flex justify-center items-center">
                  <div className="flex flex-col items-center">
                    <DatePicker
                      selected={selectedDateTime}
                      onChange={handleDateTimeChange}
                      showTimeSelect
                      timeFormat="p"
                      timeIntervals={15}
                      timeCaption="Time"
                      dateFormat="MMMM d, yyyy h:mm:ss aa"
                      minDate={new Date()}
                      minTime={set(new Date(), {
                        hours: 0,
                        minutes: 0,
                        seconds: 0,
                      })}
                      maxTime={set(new Date(), {
                        hours: 23,
                        minutes: 59,
                        seconds: 59,
                      })}
                      filterTime={filterPassedTime}
                      inline
                      calendarClassName="custom-datepicker"
                    />
                    {showError && (
                      <div className="text-red-500 mt-2">
                        Must choose a date
                      </div>
                    )}
                  </div>
                </Card>
              </TabPanel>
            </TabPanels>
          </TabGroup>
          <Title>
            {isRestore ? "Restore Note" : "Dismiss Comment"}{" "}
            {!isRestore && <span className="text-red-500">*</span>}
          </Title>
          <div className="mt-4">
            <Textarea
              value={dismissComment}
              onChange={(e) => {
                setDismissComment(e.target.value);
                setCommentError(false);
              }}
              placeholder={`Add your ${isRestore ? "restore" : "dismiss"
                } note here...`}
              error={commentError}
              errorMessage="Comment is required"
              rows={4}
            />
          </div>
          <div className="mt-4 flex justify-end gap-2">
            <Button variant="secondary" color="orange" onClick={clearAndClose}>
              Cancel
            </Button>
            <Button
              onClick={handleDismissChange}
              color="orange"
              loading={isLoading}
            >
              Dismiss
            </Button>
          </div>
        </>
      )}
    </Modal>
  );
}
