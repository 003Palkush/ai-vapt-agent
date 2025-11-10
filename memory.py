import json
from datetime import datetime
from typing import Dict, List, Any

class MemoryStore:
    """Memory store for tracking scan results and context"""
    
    def __init__(self):
        self.observations = []
        self.findings = []
        self.context = {}
        self.reasoning_trace = []
        
    def add_observation(self, tool_name: str, result: Dict[str, Any]):
        """Store observation from tool execution"""
        observation = {
            "timestamp": datetime.now().isoformat(),
            "tool": tool_name,
            "result": result,
            "success": result.get("success", False)
        }
        self.observations.append(observation)
        
        # Extract findings if present
        if "findings" in result:
            self.findings.extend(result["findings"])
    
    def add_reasoning_step(self, step: str, decision: str):
        """Track reasoning steps for transparency"""
        self.reasoning_trace.append({
            "timestamp": datetime.now().isoformat(),
            "step": step,
            "decision": decision
        })
    
    def update_context(self, key: str, value: Any):
        """Update context with new information"""
        self.context[key] = value
    
    def get_context_summary(self) -> str:
        """Generate summary of current context"""
        summary = f"Target: {self.context.get('target', 'Unknown')}\n"
        summary += f"Total Observations: {len(self.observations)}\n"
        summary += f"Total Findings: {len(self.findings)}\n"
        
        if self.findings:
            severity_counts = {}
            for finding in self.findings:
                severity = finding.get("severity", "Unknown")
                severity_counts[severity] = severity_counts.get(severity, 0) + 1
            summary += f"Severity Distribution: {severity_counts}\n"
        
        return summary
    
    def get_findings_by_severity(self) -> Dict[str, List[Dict]]:
        """Group findings by severity"""
        grouped = {"Critical": [], "High": [], "Medium": [], "Low": [], "Info": []}
        for finding in self.findings:
            severity = finding.get("severity", "Info")
            if severity in grouped:
                grouped[severity].append(finding)
        return grouped
    
    def to_dict(self) -> Dict:
        """Convert memory to dictionary for serialization"""
        return {
            "context": self.context,
            "observations": self.observations,
            "findings": self.findings,
            "reasoning_trace": self.reasoning_trace
        }
