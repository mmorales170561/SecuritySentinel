import { useRef, useEffect } from "react";
import { Link, useLocation } from "wouter";
import { useIsMobile } from "@/hooks/use-mobile";

interface SidebarProps {
  isMobileOpen: boolean;
  closeMobileMenu: () => void;
}

export function Sidebar({ isMobileOpen, closeMobileMenu }: SidebarProps) {
  const [location] = useLocation();
  const sidebarRef = useRef<HTMLElement>(null);
  const isMobile = useIsMobile();
  
  // Close mobile menu when clicking a link on mobile
  const handleLinkClick = () => {
    if (isMobile) {
      closeMobileMenu();
    }
  };
  
  // Handle clicking outside of sidebar to close on mobile
  useEffect(() => {
    function handleClickOutside(event: MouseEvent) {
      if (
        isMobileOpen &&
        sidebarRef.current &&
        !sidebarRef.current.contains(event.target as Node)
      ) {
        closeMobileMenu();
      }
    }
    
    document.addEventListener("mousedown", handleClickOutside);
    return () => {
      document.removeEventListener("mousedown", handleClickOutside);
    };
  }, [isMobileOpen, closeMobileMenu]);

  // Handle ESC key to close mobile menu
  useEffect(() => {
    function handleEscKey(event: KeyboardEvent) {
      if (event.key === "Escape" && isMobileOpen) {
        closeMobileMenu();
      }
    }
    
    document.addEventListener("keydown", handleEscKey);
    return () => {
      document.removeEventListener("keydown", handleEscKey);
    };
  }, [isMobileOpen, closeMobileMenu]);

  // Classes for mobile sidebar
  const mobileClasses = isMobileOpen
    ? "fixed inset-0 z-50 block w-full md:hidden"
    : "hidden md:block";

  return (
    <aside
      ref={sidebarRef}
      className={`w-64 bg-dark-surface border-r border-dark-border ${mobileClasses}`}
    >
      {isMobileOpen && (
        <button
          className="absolute top-4 right-4 text-white"
          onClick={closeMobileMenu}
        >
          <span className="material-icons">close</span>
        </button>
      )}
      
      <nav className="p-4">
        <div className="mb-6">
          <h2 className="text-xs uppercase tracking-wider text-gray-500 mb-3">
            Analysis Types
          </h2>
          <ul className="space-y-2">
            <li>
              <Link href="/dashboard">
                <a
                  onClick={handleLinkClick}
                  className={`flex items-center px-3 py-2 rounded-md ${
                    location.includes("dashboard")
                      ? "bg-primary bg-opacity-20 text-primary"
                      : "hover:bg-gray-800 text-gray-300"
                  }`}
                >
                  <span className="material-icons text-sm mr-3">dashboard</span>
                  <span>Risk Dashboard</span>
                </a>
              </Link>
            </li>
            <li>
              <Link href="/">
                <a
                  onClick={handleLinkClick}
                  className={`flex items-center px-3 py-2 rounded-md ${
                    location === "/" || location.includes("web")
                      ? "bg-primary bg-opacity-20 text-primary"
                      : "hover:bg-gray-800 text-gray-300"
                  }`}
                >
                  <span className="material-icons text-sm mr-3">language</span>
                  <span>Web Security Scan</span>
                </a>
              </Link>
            </li>
            <li>
              <Link href="/code">
                <a
                  onClick={handleLinkClick}
                  className={`flex items-center px-3 py-2 rounded-md ${
                    location.includes("code")
                      ? "bg-primary bg-opacity-20 text-primary"
                      : "hover:bg-gray-800 text-gray-300"
                  }`}
                >
                  <span className="material-icons text-sm mr-3">code</span>
                  <span>Code Analysis</span>
                </a>
              </Link>
            </li>
            <li>
              <Link href="/network">
                <a
                  onClick={handleLinkClick}
                  className={`flex items-center px-3 py-2 rounded-md ${
                    location.includes("network")
                      ? "bg-primary bg-opacity-20 text-primary"
                      : "hover:bg-gray-800 text-gray-300"
                  }`}
                >
                  <span className="material-icons text-sm mr-3">network_check</span>
                  <span>Network Scan</span>
                </a>
              </Link>
            </li>
            <li>
              <Link href="/api">
                <a
                  onClick={handleLinkClick}
                  className={`flex items-center px-3 py-2 rounded-md ${
                    location.includes("api")
                      ? "bg-primary bg-opacity-20 text-primary"
                      : "hover:bg-gray-800 text-gray-300"
                  }`}
                >
                  <span className="material-icons text-sm mr-3">terminal</span>
                  <span>API Testing</span>
                </a>
              </Link>
            </li>
            <li>
              <Link href="/repository">
                <a
                  onClick={handleLinkClick}
                  className={`flex items-center px-3 py-2 rounded-md ${
                    location.includes("repository")
                      ? "bg-primary bg-opacity-20 text-primary"
                      : "hover:bg-gray-800 text-gray-300"
                  }`}
                >
                  <span className="material-icons text-sm mr-3">source</span>
                  <span>Repository Scan</span>
                </a>
              </Link>
            </li>
          </ul>
        </div>

        <div className="mb-6">
          <h2 className="text-xs uppercase tracking-wider text-gray-500 mb-3">
            Tools
          </h2>
          <ul className="space-y-2">
            <li>
              <Link href="/tools">
                <a
                  onClick={handleLinkClick}
                  className={`flex items-center px-3 py-2 rounded-md ${
                    location === "/tools"
                      ? "bg-primary bg-opacity-20 text-primary"
                      : "hover:bg-gray-800 text-gray-300"
                  }`}
                >
                  <span className="material-icons text-sm mr-3">build</span>
                  <span>Integrated Tools</span>
                </a>
              </Link>
            </li>
            <li>
              <Link href="/custom-tools">
                <a
                  onClick={handleLinkClick}
                  className={`flex items-center px-3 py-2 rounded-md ${
                    location === "/custom-tools"
                      ? "bg-primary bg-opacity-20 text-primary"
                      : "hover:bg-gray-800 text-gray-300"
                  }`}
                >
                  <span className="material-icons text-sm mr-3">security</span>
                  <span>Custom Security Scanners</span>
                </a>
              </Link>
            </li>

          </ul>
        </div>

        <div>
          <h2 className="text-xs uppercase tracking-wider text-gray-500 mb-3">
            Reports
          </h2>
          <ul className="space-y-2">
            <li>
              <Link href="/history">
                <a
                  onClick={handleLinkClick}
                  className={`flex items-center px-3 py-2 rounded-md ${
                    location === "/history"
                      ? "bg-primary bg-opacity-20 text-primary"
                      : "hover:bg-gray-800 text-gray-300"
                  }`}
                >
                  <span className="material-icons text-sm mr-3">history</span>
                  <span>Scan History</span>
                </a>
              </Link>
            </li>
          </ul>
        </div>
      </nav>
    </aside>
  );
}
