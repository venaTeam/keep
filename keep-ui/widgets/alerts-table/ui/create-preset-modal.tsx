import { Button, Title } from "@tremor/react";
import Modal from "@/components/ui/Modal";
import { useState } from "react";
import { TextInput } from "@/components/ui/TextInput";

interface Props {
    isOpen: boolean;
    handleClose: () => void;
    handleCreate: (presetName: string) => void;
}

export function CreatePresetModal({ isOpen, handleClose, handleCreate }: Props) {
    const [presetName, setPresetName] = useState("");

    const clearAndClose = () => {
        setPresetName("");
        handleClose();
    };

    const onSubmit = () => {
        handleCreate(presetName);
        clearAndClose();
    };

    return (
        <Modal isOpen={isOpen} onClose={clearAndClose} className="w-[400px]" data-cy="alerts-create-preset-modal">
            <div className="flex flex-col gap-4">
                <Title>Create Preset</Title>
                <TextInput
                    placeholder="Enter preset name"
                    value={presetName}
                    onChange={(e) => setPresetName(e.target.value)}
                    data-cy="alerts-create-preset-name-input"
                />
                <div className="flex justify-end gap-2">
                    <Button variant="secondary" color="gray" onClick={clearAndClose} data-cy="alerts-create-preset-cancel-btn">
                        Cancel
                    </Button>
                    <Button
                        disabled={!presetName}
                        onClick={onSubmit}
                        color="orange"
                        data-cy="alerts-create-preset-submit-btn"
                    >
                        Create
                    </Button>
                </div>
            </div>
        </Modal>
    );
}
