import { Button } from "@/components/ui/button";
import { Link } from "wouter";

interface HeaderProps {
  toggleMobileMenu: () => void;
}

export function Header({ toggleMobileMenu }: HeaderProps) {
  return (
    <header className="bg-dark-surface border-b border-dark-border">
      <div className="container mx-auto px-4 py-3 flex justify-between items-center">
        <div className="flex items-center">
          <span className="material-icons text-primary text-3xl mr-2">security</span>
          <h1 className="text-xl font-bold text-white">SecureScan</h1>
        </div>
        <div className="flex items-center space-x-4">
          <Link href="/history">
            <Button variant="default" className="bg-primary hover:bg-blue-700 text-white">
              <span className="material-icons text-sm mr-1">history</span>
              <span>History</span>
            </Button>
          </Link>
          <Link href="/settings">
            <Button variant="outline" className="bg-dark-bg hover:bg-gray-800 text-white border-dark-border">
              <span className="material-icons text-sm mr-1">settings</span>
              <span>Settings</span>
            </Button>
          </Link>
          <div className="w-8 h-8 rounded-full bg-gray-700 flex items-center justify-center text-white">
            <span className="material-icons text-sm">person</span>
          </div>
        </div>
      </div>
      
      {/* Mobile menu button - only shown on mobile */}
      <div className="md:hidden mb-4 flex justify-between items-center px-4">
        <button
          className="text-gray-300 hover:text-white p-2"
          onClick={toggleMobileMenu}
        >
          <span className="material-icons">menu</span>
        </button>
        <div className="flex items-center">
          <span className="material-icons text-primary text-2xl mr-2">security</span>
          <h1 className="text-lg font-bold text-white">SecureScan</h1>
        </div>
        <div className="w-8 h-8 rounded-full bg-gray-700 flex items-center justify-center text-white">
          <span className="material-icons text-sm">person</span>
        </div>
      </div>
    </header>
  );
}
