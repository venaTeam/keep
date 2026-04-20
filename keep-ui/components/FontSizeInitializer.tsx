"use client";

import { useFontSize } from "@/shared/lib/hooks/useFontSize";

/** Client component that initializes the font size from localStorage on mount */
export function FontSizeInitializer() {
    useFontSize(); // This triggers the useEffect that sets document.documentElement.style.fontSize
    return null;
}
