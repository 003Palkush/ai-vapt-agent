import json
from datetime import datetime
from typing import Dict
from config import Config

class Reporter:
    """Generate structured security reports"""
    
    def generate_json_report(self, memory, executive_summary: str) -> str:
        """Generate JSON format report"""
        report = {
            "scan_metadata": {
                "timestamp": datetime.now().isoformat(),
                "target": memory.context.get("target"),
                "goal": memory.context.get("goal"),
                "agent_version": "1.0"
            },
            "executive_summary": executive_summary,
            "findings": memory.findings,
            "findings_by_severity": memory.get_findings_by_severity(),
            "observations": memory.observations,
            "reasoning_trace": memory.reasoning_trace
        }
        
        filename = f"{Config.OUTPUT_DIR}/vapt_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        with open(filename, 'w') as f:
            json.dump(report, f, indent=2)
        
        return filename
    
    def generate_markdown_report(self, memory, executive_summary: str) -> str:
        """Generate Markdown format report"""
        target = memory.context.get("target", "Unknown")
        goal = memory.context.get("goal", "Unknown")
        
        md = f"""# Security Assessment Report

## Scan Information
- **Target**: {target}
- **Goal**: {goal}
- **Timestamp**: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
- **Agent**: VAPT Agent v1.0 (Ollama Llama 3.1)

## Executive Summary

{executive_summary}

## Findings Summary

"""
        
        findings_by_severity = memory.get_findings_by_severity()
        total = sum(len(findings) for findings in findings_by_severity.values())
        md += f"**Total Findings**: {total}\n\n"
        
        for severity in ["Critical", "High", "Medium", "Low", "Info"]:
            count = len(findings_by_severity[severity])
            md += f"- **{severity}**: {count}\n"
        
        md += "\n## Detailed Findings\n\n"
        
        for severity in ["Critical", "High", "Medium", "Low", "Info"]:
            findings = findings_by_severity[severity]
            if findings:
                md += f"### {severity} Severity\n\n"
                for i, finding in enumerate(findings, 1):
                    md += f"#### {i}. {finding.get('type', 'Unknown')}\n\n"
                    md += f"**Description**: {finding.get('description', 'N/A')}\n\n"
                    if 'recommendation' in finding:
                        md += f"**Recommendation**: {finding['recommendation']}\n\n"
                    if 'port' in finding:
                        md += f"**Port**: {finding['port']}\n\n"
                    if 'header' in finding:
                        md += f"**Header**: {finding['header']}\n\n"
                    md += "---\n\n"
        
        md += "## Reasoning Trace\n\n"
        for step in memory.reasoning_trace:
            md += f"- **{step['step']}**: {step['decision']}\n"
        
        filename = f"{Config.OUTPUT_DIR}/vapt_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.md"
        with open(filename, 'w') as f:
            f.write(md)
        
        return filename
