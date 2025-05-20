import React, { useState, useEffect } from 'react';
import { useLocation } from 'wouter';

interface NavItem {
  name: string;
  path: string;
  icon: string;
  description: string;
}

interface CircularNavProps {
  items: NavItem[];
}

export function CircularNav({ items }: CircularNavProps) {
  const [location, setLocation] = useLocation();
  const [rotation, setRotation] = useState(0);
  const [activeIndex, setActiveIndex] = useState(0);
  const [isTransitioning, setIsTransitioning] = useState(false);
  
  // Calculate angle for each item
  const itemAngle = 360 / items.length;
  
  // Update rotation when active index changes
  useEffect(() => {
    const targetRotation = -(activeIndex * itemAngle);
    setRotation(targetRotation);
  }, [activeIndex, itemAngle]);
  
  // Set active index based on current path
  useEffect(() => {
    const index = items.findIndex(item => item.path === location);
    if (index > -1) {
      setActiveIndex(index);
    }
  }, [location, items]);
  
  const handleItemClick = (index: number, path: string) => {
    if (index !== activeIndex) {
      setIsTransitioning(true);
      setActiveIndex(index);
      
      // Navigate after transition
      setTimeout(() => {
        setLocation(path);
        setIsTransitioning(false);
      }, 500);
    }
  };
  
  return (
    <div className="relative w-[500px] h-[500px] mx-auto">
      {/* Center hub */}
      <div className="absolute top-1/2 left-1/2 transform -translate-x-1/2 -translate-y-1/2 w-[100px] h-[100px] rounded-full bg-gray-800 z-10 flex items-center justify-center shadow-xl">
        <div className="text-white text-xl font-bold">
          Security
        </div>
      </div>
      
      {/* Circle */}
      <div 
        className="absolute top-0 left-0 w-full h-full rounded-full border-2 border-gray-700 transition-transform duration-500 ease-in-out"
        style={{ transform: `rotate(${rotation}deg)` }}
      >
        {items.map((item, index) => {
          // Calculate position on the circle
          const angle = index * itemAngle;
          const radians = (angle * Math.PI) / 180;
          const radius = 200; // Distance from center
          const x = radius * Math.cos(radians);
          const y = radius * Math.sin(radians);
          
          // Calculate if this item is active
          const isActive = index === activeIndex;
          
          return (
            <div
              key={item.path}
              className={`absolute top-1/2 left-1/2 w-[80px] h-[80px] rounded-full flex items-center justify-center transform -translate-x-1/2 -translate-y-1/2 transition-all duration-300 cursor-pointer ${
                isActive 
                  ? 'bg-primary text-white scale-125 shadow-lg z-20' 
                  : 'bg-gray-700 text-gray-200 hover:bg-gray-600'
              }`}
              style={{
                transform: `translate(calc(-50% + ${x}px), calc(-50% + ${y}px)) rotate(${-rotation}deg)`,
              }}
              onClick={() => handleItemClick(index, item.path)}
            >
              <div className="flex flex-col items-center">
                <span className="material-icons text-xl">{item.icon}</span>
                <span className="text-xs mt-1">{item.name}</span>
              </div>
            </div>
          );
        })}
      </div>
      
      {/* Active item description */}
      <div className="absolute w-full text-center bottom-0 transform translate-y-full mt-8">
        <h3 className="text-xl font-bold text-primary">{items[activeIndex].name}</h3>
        <p className="text-gray-400 mt-2">{items[activeIndex].description}</p>
      </div>
    </div>
  );
}