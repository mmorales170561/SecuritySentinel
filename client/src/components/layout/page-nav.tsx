import React from 'react';
import { Button } from '@/components/ui/button';
import { Link } from 'wouter';

interface PageNavProps {
  title: string;
  description?: string;
}

export function PageNav({ title, description }: PageNavProps) {
  return (
    <div className="mb-6 pb-4 border-b border-gray-800">
      <div className="flex justify-between items-center">
        <div>
          <h1 className="text-2xl font-bold text-white">{title}</h1>
          {description && (
            <p className="mt-1 text-gray-400">{description}</p>
          )}
        </div>
        <Link href="/">
          <Button 
            variant="outline" 
            size="sm"
            className="bg-dark-bg hover:bg-gray-800 text-white border-dark-border"
          >
            <span className="material-icons mr-1 text-sm">home</span>
            Back to Home
          </Button>
        </Link>
      </div>
    </div>
  );
}