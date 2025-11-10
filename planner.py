from typing import List, Dict
from langchain_community.llms import Ollama
from config import Config

class Planner:
    """Goal decomposition and task planning"""
    
    def __init__(self, llm: Ollama):
        self.llm = llm
    
    def decompose_goal(self, goal: str, tool_descriptions: str) -> List[str]:
        """Break down high-level goal into sub-tasks"""
        prompt = f"""You are a security testing planner. Given a high-level goal and available tools, create a logical sequence of scanning tasks.

Goal: {goal}

{tool_descriptions}

Create a step-by-step plan using ONLY the available tools. List each step on a new line starting with the tool name.
Format: tool_name: brief reason

Example:
validate_target: Verify target is reachable
scan_ports: Identify open services
analyze_headers: Check security headers

Plan:"""
        
        try:
            response = self.llm.invoke(prompt)
            
            # Parse response into tasks
            tasks = []
            for line in response.strip().split('\n'):
                line = line.strip()
                if ':' in line and any(tool in line for tool in ['validate', 'scan', 'analyze', 'check', 'enumerate']):
                    tool_name = line.split(':')[0].strip()
                    # Clean up tool name
                    tool_name = tool_name.lstrip('1234567890.- ')
                    if tool_name:
                        tasks.append(tool_name)
            
            # Ensure validation is first
            if tasks and 'validate_target' not in tasks[0]:
                tasks.insert(0, 'validate_target')
            
            # Default plan if parsing fails
            if not tasks:
                tasks = [
                    'validate_target',
                    'scan_ports',
                    'analyze_headers',
                    'scan_vuln_patterns',
                    'check_ssl_tls'
                ]
            
            return tasks[:6]  # Limit to 6 tasks
            
        except Exception as e:
            print(f"Planning error: {e}")
            # Default fallback plan
            return [
                'validate_target',
                'scan_ports',
                'analyze_headers',
                'scan_vuln_patterns'
            ]
    
    def adapt_plan(self, current_plan: List[str], observations: str, remaining_goal: str) -> List[str]:
        """Adapt plan based on observations"""
        prompt = f"""Based on current scan results, should we modify the remaining plan?

Current observations:
{observations}

Remaining planned tasks:
{', '.join(current_plan)}

Remaining goal: {remaining_goal}

Should we: 
1. Continue with current plan
2. Skip some tasks
3. Add priority tasks

Respond with either "CONTINUE" or list modified tasks (one per line).
Response:"""
        
        try:
            response = self.llm.invoke(prompt)
            
            if "CONTINUE" in response.upper():
                return current_plan
            
            # Parse modified tasks
            modified_tasks = []
            for line in response.strip().split('\n'):
                for task in current_plan:
                    if task in line:
                        modified_tasks.append(task)
            
            return modified_tasks if modified_tasks else current_plan
            
        except:
            return current_plan
