"use client";

import React, { useState } from "react";
import { ClipboardIcon, ClipboardDocumentCheckIcon } from "@heroicons/react/24/outline";
import { clsx } from "clsx";

interface CodeBlockProps {
    text: string;
    language?: string;
    className?: string;
    maxHeight?: string;
}

/**
 * A simple, lightweight replacement for react-code-blocks' CopyBlock.
 * Uses heroicons for UI and avoids heavy syntax highlighting engines for simple use cases.
 */
export const CodeBlock: React.FC<CodeBlockProps> = ({
    text,
    language = "text",
    className,
    maxHeight = "200px",
}) => {
    const [copied, setCopied] = useState(false);

    const handleCopy = (e: React.MouseEvent) => {
        e.stopPropagation();
        navigator.clipboard.writeText(text);
        setCopied(true);
        setTimeout(() => setCopied(false), 2000);
    };

    return (
        <div
            className={clsx(
                "relative group rounded-md border border-gray-200 bg-gray-50 p-2 font-mono text-xs overflow-hidden",
                className
            )}
        >
            <div
                className="overflow-x-auto pr-10"
                style={{ maxHeight: maxHeight }}
            >
                <pre className="whitespace-pre overflow-visible">
                    <code>{text}</code>
                </pre>
            </div>
            <button
                onClick={handleCopy}
                className="absolute right-1.5 top-1.5 p-1 rounded-md hover:bg-gray-200 transition-colors text-gray-500 bg-gray-50/80 backdrop-blur-sm shadow-sm"
                title="Copy to clipboard"
            >
                {copied ? (
                    <ClipboardDocumentCheckIcon className="h-4 w-4 text-green-600" />
                ) : (
                    <ClipboardIcon className="h-4 w-4" />
                )}
            </button>
        </div>
    );
};
