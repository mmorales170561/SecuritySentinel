import { useState, useEffect, useRef } from "react";
import { cn } from "@/lib/utils";

interface CodeEditorProps {
  value: string;
  onChange: (value: string) => void;
  language?: string;
  placeholder?: string;
  className?: string;
  defaultValue?: string;
}

export function CodeEditor({
  value,
  onChange,
  language = "javascript",
  placeholder = "// Enter your code here...",
  className,
  defaultValue = "",
}: CodeEditorProps) {
  const editorRef = useRef<HTMLDivElement | null>(null);
  const [isFocused, setIsFocused] = useState(false);

  // Update the editor content if the value prop changes
  useEffect(() => {
    if (editorRef.current && editorRef.current.textContent !== value) {
      editorRef.current.textContent = value || defaultValue;
    }
  }, [value, defaultValue]);

  const handleInput = () => {
    if (editorRef.current) {
      onChange(editorRef.current.textContent || "");
    }
  };

  return (
    <div
      className={cn(
        "bg-dark-bg border border-dark-border rounded-lg p-4 code-editor font-mono text-sm overflow-auto whitespace-pre",
        isFocused ? "ring-2 ring-primary" : "",
        className
      )}
      ref={editorRef}
      contentEditable
      spellCheck="false"
      onInput={handleInput}
      onFocus={() => setIsFocused(true)}
      onBlur={() => setIsFocused(false)}
      suppressContentEditableWarning={true}
      role="textbox"
      aria-multiline="true"
      data-language={language}
      placeholder={placeholder}
    >
      {value || defaultValue}
    </div>
  );
}
