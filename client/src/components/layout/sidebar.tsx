import { useRef, useEffect } from "react";
import { Link, useLocation } from "wouter";

export function Sidebar({ isMobileOpen, closeMobileMenu }) {
  const [location] = useLocation();
  const sidebarRef = useRef<HTMLElement>(null);
  
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
              <Link href="/">
                <a
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
              <a
                href="#"
                className="flex items-center px-3 py-2 rounded-md hover:bg-gray-800 text-gray-300"
              >
                <span className="material-icons text-sm mr-3">bug_report</span>
                <span>Burp Suite</span>
              </a>
            </li>
            <li>
              <a
                href="#"
                className="flex items-center px-3 py-2 rounded-md hover:bg-gray-800 text-gray-300"
              >
                <span className="material-icons text-sm mr-3">security</span>
                <span>OWASP ZAP</span>
              </a>
            </li>
            <li>
              <a
                href="#"
                className="flex items-center px-3 py-2 rounded-md hover:bg-gray-800 text-gray-300"
              >
                <span className="material-icons text-sm mr-3">wifi_tethering</span>
                <span>Nmap</span>
              </a>
            </li>
            <li>
              <a
                href="#"
                className="flex items-center px-3 py-2 rounded-md hover:bg-gray-800 text-gray-300"
              >
                <span className="material-icons text-sm mr-3">insights</span>
                <span>SonarQube</span>
              </a>
            </li>
            <li>
              <a
                href="#"
                className="flex items-center px-3 py-2 rounded-md hover:bg-gray-800 text-gray-300"
              >
                <span className="material-icons text-sm mr-3">find_in_page</span>
                <span>Semgrep</span>
              </a>
            </li>
          </ul>
        </div>

        <div>
          <h2 className="text-xs uppercase tracking-wider text-gray-500 mb-3">
            Recent Scans
          </h2>
          <ul className="space-y-2">
            <li>
              <a
                href="#"
                className="flex items-center px-3 py-2 rounded-md hover:bg-gray-800 text-gray-300 text-sm"
              >
                <span className="material-icons text-xs mr-2">schedule</span>
                <span className="truncate">example.com (2 hours ago)</span>
              </a>
            </li>
            <li>
              <a
                href="#"
                className="flex items-center px-3 py-2 rounded-md hover:bg-gray-800 text-gray-300 text-sm"
              >
                <span className="material-icons text-xs mr-2">schedule</span>
                <span className="truncate">auth-service.js (1 day ago)</span>
              </a>
            </li>
            <li>
              <a
                href="#"
                className="flex items-center px-3 py-2 rounded-md hover:bg-gray-800 text-gray-300 text-sm"
              >
                <span className="material-icons text-xs mr-2">schedule</span>
                <span className="truncate">api.company.com (3 days ago)</span>
              </a>
            </li>
          </ul>
        </div>
      </nav>
    </aside>
  );
}
