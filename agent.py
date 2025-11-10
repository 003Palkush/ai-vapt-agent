import sys
from typing import Dict, Any
from langchain_ollama import OllamaLLM
from colorama import init, Fore, Style

from config import Config
from memory import MemoryStore
from tools import ToolRegistry
from planner import Planner
from reporter import Reporter

init(autoreset=True)

class VAPTAgent:
    """AI-Powered VAPT Agent with reasoning loop"""
    
    def __init__(self):
        Config.ensure_output_dir()
        
        print(f"{Fore.CYAN}Initializing VAPT Agent...{Style.RESET_ALL}")
        
        try:
            self.llm = OllamaLLM(
                model=Config.OLLAMA_MODEL,
                base_url=Config.OLLAMA_BASE_URL,
                temperature=0.7
            )
            print(f"{Fore.CYAN}Testing LLM connection...{Style.RESET_ALL}")
            test_response = self.llm.invoke("Hello")
            print(f"{Fore.GREEN}✓ LLM connection successful{Style.RESET_ALL}")
        except Exception as e:
            print(f"{Fore.RED}Error: Could not connect to Ollama{Style.RESET_ALL}")
            print(f"{Fore.YELLOW}Make sure Ollama is running: ollama serve{Style.RESET_ALL}")
            print(f"{Fore.YELLOW}Check available models: ollama list{Style.RESET_ALL}")
            print(f"{Fore.YELLOW}Current model setting: {Config.OLLAMA_MODEL}{Style.RESET_ALL}")
            print(f"\n{Fore.RED}Error details: {str(e)}{Style.RESET_ALL}")
            raise e
        
        self.memory = MemoryStore()
        self.tools = ToolRegistry()
        self.planner = Planner(self.llm)
        self.reporter = Reporter()
        
        print(f"{Fore.GREEN}✓ Agent initialized with {Config.OLLAMA_MODEL}{Style.RESET_ALL}")
    
    def execute_goal(self, goal: str, target: str):
        """Main execution loop for goal-based testing"""
        print(f"\n{Fore.YELLOW}{'='*60}{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}Goal: {goal}{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}Target: {target}{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}{'='*60}{Style.RESET_ALL}\n")
        
        self.memory.update_context("target", target)
        self.memory.update_context("goal", goal)
        
        print(f"{Fore.CYAN}[Planning Phase] Decomposing goal into tasks...{Style.RESET_ALL}")
        tool_descriptions = self.tools.get_tool_descriptions()
        task_plan = self.planner.decompose_goal(goal, tool_descriptions)
        
        print(f"{Fore.GREEN}✓ Generated plan with {len(task_plan)} tasks{Style.RESET_ALL}")
        for i, task in enumerate(task_plan, 1):
            print(f"  {i}. {task}")
        
        self.memory.add_reasoning_step("Planning", f"Generated task plan: {', '.join(task_plan)}")
        
        print(f"\n{Fore.CYAN}[Execution Phase] Running scanning tools...{Style.RESET_ALL}")
        
        normalized_target = target
        
        for iteration, task_name in enumerate(task_plan, 1):
            if iteration > Config.MAX_REASONING_ITERATIONS:
                print(f"{Fore.RED}Max iterations reached{Style.RESET_ALL}")
                break
            
            print(f"\n{Fore.BLUE}--- Iteration {iteration}/{len(task_plan)} ---{Style.RESET_ALL}")
            print(f"{Fore.BLUE}Executing: {task_name}{Style.RESET_ALL}")
            
            result = self.tools.execute_tool(task_name, target=normalized_target)
            
            if task_name == "validate_target" and result.get("success") and "normalized_target" in result:
                normalized_target = result["normalized_target"]
                self.memory.update_context("normalized_target", normalized_target)
                print(f"{Fore.CYAN}  → Using normalized target: {normalized_target}{Style.RESET_ALL}")
            
            self.memory.add_observation(task_name, result)
            
            if result.get("success"):
                findings_count = len(result.get("findings", []))
                print(f"{Fore.GREEN}✓ {task_name} completed - {findings_count} findings{Style.RESET_ALL}")
                
                if findings_count > 0:
                    findings = result.get("findings", [])
                    severity_counts = {}
                    for f in findings:
                        sev = f.get("severity", "Unknown")
                        severity_counts[sev] = severity_counts.get(sev, 0) + 1
                    summary = ", ".join([f"{count} {sev}" for sev, count in severity_counts.items()])
                    print(f"{Fore.CYAN}  → {summary}{Style.RESET_ALL}")
            else:
                error = result.get("error", "Unknown error")
                print(f"{Fore.RED}✗ {task_name} failed: {error}{Style.RESET_ALL}")
            
            self._reason_about_results(task_name, result)
        
        print(f"\n{Fore.CYAN}[Reporting Phase] Generating final report...{Style.RESET_ALL}")
        self._generate_final_report()
    
    def _reason_about_results(self, task_name: str, result: Dict[str, Any]):
        """Reason about task results and decide next steps"""
        findings = result.get("findings", [])
        
        if not findings:
            reasoning = f"No vulnerabilities found in {task_name}"
        else:
            high_severity = [f for f in findings if f.get("severity") in ["Critical", "High"]]
            if high_severity:
                reasoning = f"Found {len(high_severity)} critical/high severity issues in {task_name}"
            else:
                reasoning = f"Found {len(findings)} lower severity issues in {task_name}"
        
        self.memory.add_reasoning_step(task_name, reasoning)
        print(f"{Fore.MAGENTA}  → Reasoning: {reasoning}{Style.RESET_ALL}")
    
    def _generate_final_report(self):
        """Generate comprehensive security report"""
        print(f"\n{Fore.CYAN}Analyzing findings with LLM...{Style.RESET_ALL}")
        
        findings_summary = self._format_findings_for_llm()
        
        summary_prompt = f"""You are a security analyst. Write a concise 2-3 sentence executive summary of this security assessment:

Target: {self.memory.context.get('target')}
Total Findings: {len(self.memory.findings)}

{findings_summary}

Write an executive summary focusing on the key security issues found:"""
        
        try:
            executive_summary = self.llm.invoke(summary_prompt)
            executive_summary = executive_summary.strip()
            
            if not executive_summary or len(executive_summary) < 20:
                raise Exception("Empty or invalid LLM response")
                
        except Exception as e:
            print(f"{Fore.YELLOW}⚠ Warning: Could not generate AI summary{Style.RESET_ALL}")
            print(f"{Fore.YELLOW}  Generating manual summary instead...{Style.RESET_ALL}")
            
            findings_by_severity = self.memory.get_findings_by_severity()
            critical_count = len(findings_by_severity["Critical"])
            high_count = len(findings_by_severity["High"])
            medium_count = len(findings_by_severity["Medium"])
            low_count = len(findings_by_severity["Low"])
            total_count = len(self.memory.findings)
            
            if critical_count > 0 or high_count > 0:
                executive_summary = f"Security assessment identified {total_count} findings, including {critical_count} critical and {high_count} high severity issues that require immediate attention. The target shows security misconfigurations that should be addressed to improve overall security posture."
            elif medium_count > 0:
                executive_summary = f"Security assessment identified {total_count} findings, primarily of medium severity. While no critical vulnerabilities were detected, several security improvements are recommended to enhance the target's security posture."
            elif low_count > 0:
                executive_summary = f"Security assessment completed with {total_count} low-severity findings. The target shows reasonable security controls, though minor improvements are recommended."
            else:
                executive_summary = f"Security assessment completed. No significant vulnerabilities were detected. The target appears to have basic security controls in place."
        
        json_path = self.reporter.generate_json_report(self.memory, executive_summary)
        md_path = self.reporter.generate_markdown_report(self.memory, executive_summary)
        
        print(f"\n{Fore.GREEN}{'='*60}{Style.RESET_ALL}")
        print(f"{Fore.GREEN}SCAN COMPLETE{Style.RESET_ALL}")
        print(f"{Fore.GREEN}{'='*60}{Style.RESET_ALL}")
        print(f"\n{Fore.CYAN}Executive Summary:{Style.RESET_ALL}")
        print(f"{Fore.WHITE}{executive_summary}{Style.RESET_ALL}")
        print(f"\n{Fore.CYAN}Reports generated:{Style.RESET_ALL}")
        print(f"  📄 JSON: {json_path}")
        print(f"  📝 Markdown: {md_path}")
        
        findings_by_severity = self.memory.get_findings_by_severity()
        print(f"\n{Fore.CYAN}Findings Summary:{Style.RESET_ALL}")
        
        total_findings = sum(len(findings) for findings in findings_by_severity.values())
        
        if total_findings == 0:
            print(f"  {Fore.WHITE}No vulnerabilities detected{Style.RESET_ALL}")
        else:
            for severity in ["Critical", "High", "Medium", "Low", "Info"]:
                count = len(findings_by_severity[severity])
                if count > 0:
                    color = {
                        "Critical": Fore.RED,
                        "High": Fore.RED,
                        "Medium": Fore.YELLOW,
                        "Low": Fore.BLUE,
                        "Info": Fore.WHITE
                    }.get(severity, Fore.WHITE)
                    print(f"  {color}{severity}: {count}{Style.RESET_ALL}")
        
        if total_findings > 0:
            print(f"\n{Fore.CYAN}Top Findings:{Style.RESET_ALL}")
            shown = 0
            for severity in ["Critical", "High", "Medium"]:
                for finding in findings_by_severity[severity]:
                    if shown >= 5:
                        break
                    color = {"Critical": Fore.RED, "High": Fore.RED, "Medium": Fore.YELLOW}.get(severity, Fore.WHITE)
                    print(f"  {color}• [{severity}] {finding.get('type', 'Unknown')}: {finding.get('description', 'N/A')}{Style.RESET_ALL}")
                    shown += 1
                if shown >= 5:
                    break
            
            if total_findings > 5:
                print(f"  {Fore.WHITE}... and {total_findings - 5} more (see full report){Style.RESET_ALL}")
    
    def _format_findings_for_llm(self) -> str:
        """Format findings for LLM analysis"""
        findings_by_severity = self.memory.get_findings_by_severity()
        formatted = ""
        
        for severity in ["Critical", "High", "Medium", "Low"]:
            findings = findings_by_severity[severity]
            if findings:
                formatted += f"\n{severity} ({len(findings)}):\n"
                for f in findings[:3]:
                    formatted += f"- {f.get('type', 'Unknown')}: {f.get('description', 'N/A')}\n"
        
        return formatted if formatted else "No significant findings"


def main():
    """Main entry point"""
    print(f"{Fore.CYAN}")
    print("╔═══════════════════════════════════════════════════════════╗")
    print("║         AI-Powered VAPT Agent v1.0                        ║")
    print("║         Powered by Ollama Llama 3.1                       ║")
    print("╚═══════════════════════════════════════════════════════════╝")
    print(Style.RESET_ALL)
    
    agent = VAPTAgent()
    
    if len(sys.argv) > 2:
        goal = sys.argv[1]
        target = sys.argv[2]
    else:
        print(f"\n{Fore.YELLOW}Enter scan details:{Style.RESET_ALL}")
        goal = input("Goal (e.g., 'Scan for web vulnerabilities'): ").strip()
        target = input("Target (e.g., 'example.com' or 'https://example.com'): ").strip()
    
    if not goal or not target:
        print(f"{Fore.RED}Error: Goal and target are required{Style.RESET_ALL}")
        sys.exit(1)
    
    try:
        agent.execute_goal(goal, target)
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}⚠️  Scan interrupted by user{Style.RESET_ALL}")
    except Exception as e:
        print(f"\n{Fore.RED}❌ Error during scan: {str(e)}{Style.RESET_ALL}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    main()
