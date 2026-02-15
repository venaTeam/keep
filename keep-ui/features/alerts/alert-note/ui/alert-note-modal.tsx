"use client";

import React, { useEffect, useState } from "react";
import { Button, Textarea } from "@tremor/react";
import { AlertDto } from "@/entities/alerts/model";
import Modal from "@/components/ui/Modal";
import { useApi } from "@/shared/lib/hooks/useApi";
import { showErrorToast } from "@/shared/ui";

interface AlertNoteModalProps {
  handleClose: () => void;
  alert: AlertDto | null;
  readOnly?: boolean;
  mutate?: () => void;
}

export const AlertNoteModal = ({
  handleClose,
  alert,
  readOnly = false,
  mutate,
}: AlertNoteModalProps) => {
  const api = useApi();
  const [noteContent, setNoteContent] = useState<string>("");

  useEffect(() => {
    if (alert) {
      setNoteContent(alert.note || "");
    }
  }, [alert]);

  // if this modal should not be open, do nothing
  if (!alert) return null;

  const saveNote = async () => {
    try {
      const trimmedNote = noteContent.trim();

      if (trimmedNote) {
        // Save the note via enrich
        const requestData = {
          note: trimmedNote,
          fingerprint: alert.fingerprint,
        };
        await api.post(`/alerts/enrich/note`, requestData);
        // Update local alert object with the trimmed note
        alert.note = trimmedNote;
      } else {
        // Empty note — remove it via unenrich so the note column disappears
        await api.post(`/alerts/unenrich`, {
          fingerprint: alert.fingerprint,
          enrichments: ["note"],
        });
        // Clear the local alert note
        alert.note = undefined;
      }

      setNoteContent("");
      mutate?.();
      handleClose();
    } catch (error) {
      showErrorToast(error, "Failed to save note");
    }
  };

  const isOpen = alert !== null;

  const handleNoteClose = () => {
    setNoteContent("");
    handleClose();
  };

  return (
    <Modal
      isOpen={isOpen}
      onClose={handleClose}
      beforeTitle={alert?.name}
      title="Add Note"
    >
      <div className="mt-4">
        <Textarea
          value={noteContent}
          onChange={(e) => setNoteContent(e.target.value)}
          placeholder="Add your note here..."
          rows={6}
          disabled={readOnly}
        />
      </div>
      <div className="mt-4 flex justify-end gap-2">
        <Button // Use Tremor button for Cancel
          onClick={handleNoteClose}
          variant="secondary"
          color="orange"
        >
          {readOnly ? "Close" : "Cancel"}
        </Button>
        {!readOnly && (
          <Button // Use Tremor button for Save
            onClick={saveNote}
            color="orange"
          >
            Save
          </Button>
        )}
      </div>
    </Modal>
  );
};
