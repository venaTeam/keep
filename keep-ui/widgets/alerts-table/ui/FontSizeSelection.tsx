"use client";

import { Button } from "@tremor/react";
import { FontSize, useFontSize } from "@/shared/lib/hooks/useFontSize";

interface FontSizeSelectionProps {
    onClose?: () => void;
}

export function FontSizeSelection({ onClose }: FontSizeSelectionProps) {
    const { fontSize, setFontSize, fontSizeOptions } = useFontSize();

    const labels: Record<FontSize, string> = {
        small: "Small",
        medium: "Medium",
        large: "Large",
    };

    const previews: Record<FontSize, string> = {
        small: "14px",
        medium: "16px",
        large: "18px",
    };

    return (
        <div className="flex flex-col gap-4">
            <p className="text-sm text-gray-500">
                Select the font size for the entire interface.
            </p>
            <div className="flex flex-col gap-2">
                {fontSizeOptions.map((size) => (
                    <button
                        key={size}
                        onClick={() => setFontSize(size)}
                        className={`flex items-center justify-between px-4 py-3 rounded-lg border transition-all ${fontSize === size
                            ? "border-orange-500 bg-orange-50 text-orange-700"
                            : "border-gray-200 hover:border-orange-300 hover:bg-orange-50/50 text-gray-700"
                            }`}
                    >
                        <span
                            className="font-medium"
                            style={{ fontSize: previews[size] }}
                        >
                            {labels[size]}
                        </span>
                        <span className="text-xs text-gray-400">{previews[size]}</span>
                    </button>
                ))}
            </div>
            {onClose && (
                <div className="flex justify-end mt-2">
                    <Button color="orange" size="xs" onClick={onClose}>
                        Done
                    </Button>
                </div>
            )}
        </div>
    );
}
