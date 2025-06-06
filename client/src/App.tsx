import { Switch, Route } from "wouter";
import { queryClient } from "./lib/queryClient";
import { QueryClientProvider } from "@tanstack/react-query";
import { Toaster } from "@/components/ui/toaster";
import { TooltipProvider } from "@/components/ui/tooltip";
import NotFound from "@/pages/not-found";
import Home from "@/pages/home";
import Dashboard from "@/pages/dashboard";
import CodeAnalysis from "@/pages/code";
import NetworkScan from "@/pages/network";
import ApiTesting from "@/pages/api";
import RepositoryScan from "@/pages/repository";
import Settings from "@/pages/settings";
import ToolsIntegration from "@/pages/tools";
import CustomTools from "@/pages/custom-tools";
import History from "@/pages/history";
import { useToast } from "@/hooks/use-toast";

function Router() {
  return (
    <Switch>
      <Route path="/" component={Home} />
      <Route path="/dashboard" component={Dashboard} />
      <Route path="/code" component={CodeAnalysis} />
      <Route path="/network" component={NetworkScan} />
      <Route path="/api" component={ApiTesting} />
      <Route path="/repository" component={RepositoryScan} />
      <Route path="/settings" component={Settings} />
      <Route path="/tools" component={ToolsIntegration} />
      <Route path="/custom-tools" component={CustomTools} />
      <Route path="/history" component={History} />
      <Route component={NotFound} />
    </Switch>
  );
}

function App() {
  return (
    <QueryClientProvider client={queryClient}>
      <TooltipProvider>
        <div className="min-h-screen flex flex-col dark:bg-[#121212] dark:text-[#E0E0E0]">
          <Toaster />
          <Router />
        </div>
      </TooltipProvider>
    </QueryClientProvider>
  );
}

export default App;
