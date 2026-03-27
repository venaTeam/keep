"use client";

import { useLocalStorage } from "@/utils/hooks/useLocalStorage";
import { useEffect } from "react";

export type FontSize = "small" | "medium" | "large";

const FONT_SIZE_MAP: Record<FontSize, string> = {
    small: "14px",
    medium: "16px",
    large: "18px",
};

export function useFontSize() {
    const [fontSize, setFontSize] = useLocalStorage<FontSize>(
        "keep-ui-font-size",
        "medium"
    );

    useEffect(() => {
        document.documentElement.style.fontSize = FONT_SIZE_MAP[fontSize];
    }, [fontSize]);

    return { fontSize, setFontSize, fontSizeOptions: Object.keys(FONT_SIZE_MAP) as FontSize[] };
}
