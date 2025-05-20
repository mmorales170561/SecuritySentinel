import React from 'react';
import { Button } from '@/components/ui/button';
import { useLocation } from 'wouter';

interface PageHeaderProps {
  title: string;
  description?: string;
  showBackButton?: boolean;
  backPath?: string;
}

export function PageHeader({ 
  title, 
  description, 
  showBackButton = true,
  backPath = '/' 
}: PageHeaderProps) {
  const [, navigate] = useLocation();
  
  return (
    <div className="mb-6 pb-4 border-b border-gray-800">
      <div className="flex justify-between items-center">
        <div>
          <h1 className="text-2xl font-bold text-white">{title}</h1>
          {description && (
            <p className="mt-1 text-gray-400">{description}</p>
          )}
        </div>
        {showBackButton && (
          <Button 
            variant="outline" 
            size="sm"
            onClick={() => navigate(backPath)}
          >
            <span className="material-icons mr-1 text-sm">home</span>
            Home
          </Button>
        )}
      </div>
    </div>
  );
}