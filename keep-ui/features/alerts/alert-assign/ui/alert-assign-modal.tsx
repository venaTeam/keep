import { Button, Title, Subtitle, Textarea } from "@tremor/react";
import Modal from "@/components/ui/Modal";
import { useState } from "react";
import { AlertDto } from "@/entities/alerts/model";
import { toast } from "react-toastify";
import { useAlerts } from "@/entities/alerts/model/useAlerts";
import { useApi } from "@/shared/lib/hooks/useApi";
import { showErrorToast } from "@/shared/ui";
import { useRevalidateMultiple } from "@/shared/lib/state-utils";

interface Props {
    alert: AlertDto | null | undefined;
    handleClose: () => void;
    presetName: string;
}

export function AlertAssignModal({
    alert,
    handleClose,
    presetName,
}: Props) {
    const api = useApi();
    const [disposeOnNewAlert, setDisposeOnNewAlert] = useState(false);
    const revalidateMultiple = useRevalidateMultiple();
    const { alertsMutator } = useAlerts();
    const presetsMutator = () => revalidateMultiple(["/preset"]);
    const [noteContent, setNoteContent] = useState<string>("");

    if (!alert) return null;

    const clearAndClose = () => {
        setNoteContent("");
        setDisposeOnNewAlert(false);
        handleClose();
    };

    const handleAssign = async () => {
        try {
            const lastReceived =
                typeof alert.lastReceived === "string"
                    ? alert.lastReceived
                    : alert.lastReceived.toISOString();

            await api.post(
                `/alerts/${alert.fingerprint}/assign/${lastReceived}`,
                {
                    dispose_on_new_alert: disposeOnNewAlert,
                    note: noteContent && noteContent.trim() !== "" ? noteContent.trim() : null,
                }
            );

            toast.success("Alert assigned successfully!");
            clearAndClose();
            await alertsMutator();
            await presetsMutator();
        } catch (error) {
            showErrorToast(error, "Failed to assign alert.");
        }
    };

    return (
        <Modal onClose={handleClose} isOpen={!!alert} className="!max-w-none !w-auto inline-block whitespace-nowrap overflow-visible">
            <Title className="text-lg font-semibold">Assign Alert</Title>
            <div className="border-t border-gray-200 my-4" />
            <div className="flex mt-2.5 inline-flex items-center">
                <Subtitle className="flex items-center bold mr-4">
                    Assign to me
                </Subtitle>
                <Button
                    variant={disposeOnNewAlert ? "primary" : "secondary"}
                    size="xs"
                    onClick={() => setDisposeOnNewAlert(!disposeOnNewAlert)}
                    tooltip={disposeOnNewAlert ? "Dispose the assignment when a new alert comes in." : "Keep the assignment when a new alert comes in."}
                >
                    {disposeOnNewAlert ? "Disposing on new alerts" : "Keeping on new alerts"}
                </Button>
            </div>
            <div className="mt-4">
                <Subtitle>Add Note</Subtitle>
                <div className="mt-4">
                    <Textarea
                        value={noteContent}
                        onChange={(e) => setNoteContent(e.target.value)}
                        placeholder="Add a note..."
                        rows={4}
                    />
                </div>
            </div>
            <div className="flex justify-end mt-4 gap-2">
                <Button onClick={handleClose} color="orange" variant="secondary">
                    Cancel
                </Button>
                <Button onClick={handleAssign} color="orange">
                    Assign
                </Button>
            </div>
        </Modal>
    );
}
