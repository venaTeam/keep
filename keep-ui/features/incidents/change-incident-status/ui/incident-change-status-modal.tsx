import { Button, Title, Subtitle, Textarea } from "@tremor/react";
import Modal from "@/components/ui/Modal";
import { useState, useEffect } from "react";
import { Status } from "@/entities/incidents/model";
import { STATUS_ICONS } from "@/entities/incidents/ui";
import { useIncidentActions } from "@/entities/incidents/model";
import { Select, showErrorToast } from "@/shared/ui";
import { capitalize } from "@/utils/helpers";

interface Props {
    incidentId: string;
    currentStatus: Status;
    initialStatus?: Status | null;
    isOpen: boolean;
    onClose: () => void;
    onSuccess?: (newStatus: Status) => void;
}

export function IncidentChangeStatusModal({
    incidentId,
    currentStatus,
    initialStatus,
    isOpen,
    onClose,
    onSuccess,
}: Props) {
    const [disposeOnNewAlert, setDisposeOnNewAlert] = useState(false);
    const [selectedStatus, setSelectedStatus] = useState<Status | null>(initialStatus ?? null);
    const [noteContent, setNoteContent] = useState<string>("");
    const [isSubmitting, setIsSubmitting] = useState(false);
    const { changeStatus } = useIncidentActions();

    useEffect(() => {
        if (initialStatus) {
            setSelectedStatus(initialStatus);
        }
    }, [initialStatus]);

    const statusOptions = Object.values(Status)
        .filter((status) => status !== currentStatus && status !== Status.Deleted)
        .map((status) => ({
            value: status,
            label: (
                <div className="flex items-center gap-2">
                    {STATUS_ICONS[status]}
                    <span>{capitalize(status)}</span>
                </div>
            ),
        }));

    const clearAndClose = () => {
        setSelectedStatus(null);
        setNoteContent("");
        setDisposeOnNewAlert(false);
        onClose();
    };

    const handleChangeStatus = async () => {
        if (!selectedStatus) {
            showErrorToast(new Error("Please select a new status."));
            return;
        }
        try {
            setIsSubmitting(true);
            await changeStatus(
                incidentId,
                selectedStatus,
                noteContent?.trim() || undefined,
                disposeOnNewAlert
            );
            onSuccess?.(selectedStatus);
            clearAndClose();
        } catch (error) {
            showErrorToast(error, "Failed to change incident status.");
        } finally {
            setIsSubmitting(false);
        }
    };

    return (
        <Modal
            onClose={clearAndClose}
            isOpen={isOpen}
            className="!max-w-none !w-auto inline-block whitespace-nowrap overflow-visible"
        >
            <Title className="text-lg font-semibold">Change Incident Status</Title>
            <div className="border-t border-gray-200 my-4" />
            <div className="flex mt-2.5 inline-flex items-center">
                <Subtitle className="flex items-center bold">New status:</Subtitle>
                <Select
                    options={statusOptions}
                    value={statusOptions.find(
                        (option) => option.value === selectedStatus
                    )}
                    onChange={(option) => setSelectedStatus(option?.value || null)}
                    placeholder="Select new status"
                    className="ml-2"
                    styles={{
                        control: (base) => ({
                            ...base,
                            width: "max-content",
                            minWidth: "180px",
                        }),
                    }}
                />
                <Button
                    variant={disposeOnNewAlert ? "primary" : "secondary"}
                    className="ml-4"
                    size="xs"
                    onClick={() => setDisposeOnNewAlert(!disposeOnNewAlert)}
                    tooltip={
                        disposeOnNewAlert
                            ? "Dispose the status when a new alert comes in."
                            : "Keep the status when a new alert comes in."
                    }
                >
                    {disposeOnNewAlert
                        ? "Disposing on new alerts"
                        : "Keeping on new alerts"}
                </Button>
            </div>
            <div className="mt-4">
                <Subtitle>Add Note</Subtitle>
                <div className="mt-4">
                    <Textarea
                        value={noteContent}
                        onChange={(e) => setNoteContent(e.target.value)}
                        placeholder="Add the reason for status change here..."
                        rows={4}
                    />
                </div>
            </div>
            <div className="flex justify-end mt-4 gap-2">
                <Button onClick={clearAndClose} color="orange" variant="secondary">
                    Cancel
                </Button>
                <Button
                    onClick={handleChangeStatus}
                    color="orange"
                    disabled={isSubmitting}
                    loading={isSubmitting}
                >
                    Change Status
                </Button>
            </div>
        </Modal>
    );
}
