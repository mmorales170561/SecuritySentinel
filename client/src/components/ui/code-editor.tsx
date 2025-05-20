import React, { useState } from 'react';
import { cn } from '@/lib/utils';
import { Textarea } from '@/components/ui/textarea';

interface CodeEditorProps {
  value: string;
  onChange: (value: string) => void;
  language?: string;
  className?: string;
}

export function CodeEditor({ value, onChange, language, className }: CodeEditorProps) {
  return (
    <Textarea
      value={value}
      onChange={(e) => onChange(e.target.value)}
      className={cn(
        'font-mono text-sm leading-relaxed min-h-[200px]',
        className
      )}
      spellCheck="false"
    />
  );
}