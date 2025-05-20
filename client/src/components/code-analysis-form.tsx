import { useState } from "react";
import { Button } from "@/components/ui/button";
import { Label } from "@/components/ui/label";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { CodeEditor } from "@/components/ui/code-editor";
import { useMutation } from "@tanstack/react-query";
import { apiRequest } from "@/lib/queryClient";
import { useToast } from "@/hooks/use-toast";
import { CodeAnalysisRequest } from "@shared/schema";

interface CodeAnalysisFormProps {
  onAnalysisStart: (scanId: number) => void;
}

export function CodeAnalysisForm({ onAnalysisStart }: CodeAnalysisFormProps) {
  const { toast } = useToast();
  const [language, setLanguage] = useState("python");
  const [code, setCode] = useState(
`def authenticate(username, password):
    # Connect to database
    connection = connect_to_db()
    
    # Execute query
    query = "SELECT * FROM users WHERE username = '" + username + "' AND password = '" + password + "'"
    result = connection.execute(query)
    
    # Check if user exists
    if result.rowcount > 0:
        return True
    else:
        return False`
  );

  const analyzeCodeMutation = useMutation({
    mutationFn: async (codeRequest: CodeAnalysisRequest) => {
      const response = await apiRequest("POST", "/api/scan/code", codeRequest);
      return await response.json();
    },
    onSuccess: (data) => {
      toast({
        title: "Analysis started",
        description: `Analyzing ${language} code snippet`,
      });
      onAnalysisStart(data.scanId);
    },
    onError: (error) => {
      toast({
        title: "Error",
        description: `Failed to start code analysis: ${error.message}`,
        variant: "destructive",
      });
    },
  });

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    
    const codeRequest: CodeAnalysisRequest = {
      language,
      code,
    };
    
    analyzeCodeMutation.mutate(codeRequest);
  };

  return (
    <div className="bg-dark-surface rounded-lg p-4 md:p-6 mb-6">
      <h2 className="text-xl font-bold mb-4">Code Analysis</h2>
      
      <form className="space-y-4" onSubmit={handleSubmit}>
        <div>
          <Label htmlFor="language-select" className="block text-sm font-medium mb-1">
            Language
          </Label>
          <Select value={language} onValueChange={setLanguage}>
            <SelectTrigger id="language-select" className="bg-dark-bg border border-dark-border text-white rounded-lg">
              <SelectValue placeholder="Select language" />
            </SelectTrigger>
            <SelectContent className="bg-dark-bg border border-dark-border text-white">
              <SelectItem value="python">Python</SelectItem>
              <SelectItem value="javascript">JavaScript</SelectItem>
              <SelectItem value="php">PHP</SelectItem>
              <SelectItem value="java">Java</SelectItem>
              <SelectItem value="csharp">C#</SelectItem>
              <SelectItem value="go">Go</SelectItem>
            </SelectContent>
          </Select>
        </div>
        
        <div>
          <Label htmlFor="code-editor" className="block text-sm font-medium mb-1">
            Code Snippet
          </Label>
          <CodeEditor
            value={code}
            onChange={setCode}
            language={language}
            className="min-h-[200px]"
          />
        </div>
        
        <div className="flex justify-end">
          <Button type="button" variant="secondary" className="mr-2">
            Upload File
          </Button>
          <Button 
            type="submit" 
            className="bg-primary hover:bg-blue-700 text-white flex items-center"
            disabled={analyzeCodeMutation.isPending}
          >
            <span className="material-icons text-sm mr-1">code</span>
            <span>Analyze Code</span>
          </Button>
        </div>
      </form>
    </div>
  );
}
