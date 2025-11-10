#!/usr/bin/env python3
"""
AI-Powered VAPT Agent - Main Entry Point
Run: python main.py
"""

import sys
import os
from colorama import init, Fore, Style

# Initialize colorama for cross-platform colored output
init(autoreset=True)

def check_dependencies():
    """Check if all required dependencies are installed"""
    missing = []
    
    try:
        import requests
    except ImportError:
        missing.append("requests")
    
    try:
        from langchain_community.llms import Ollama
    except ImportError:
        missing.append("langchain-community")
    
    try:
        from colorama import Fore
    except ImportError:
        missing.append("colorama")
    
    if missing:
        print(f"{Fore.RED}❌ Missing dependencies: {', '.join(missing)}{Style.RESET_ALL}")
        print(f"\n{Fore.YELLOW}Install with:{Style.RESET_ALL}")
        print(f"  pip install {' '.join(missing)}")
        sys.exit(1)

def check_ollama():
    """Check if Ollama is running"""
    import requests
    
    try:
        response = requests.get("http://localhost:11434/api/tags", timeout=5)
        if response.status_code == 200:
            return True
    except:
        pass
    
    print(f"{Fore.RED}❌ Ollama is not running!{Style.RESET_ALL}\n")
    print(f"{Fore.YELLOW}To start Ollama:{Style.RESET_ALL}")
    print(f"  1. Open a new terminal")
    print(f"  2. Run: ollama serve")
    print(f"  3. Keep that terminal open")
    print(f"  4. In another terminal, run: ollama pull llama3.1:8b")
    print(f"  5. Then run this script again\n")
    sys.exit(1)

def print_banner():
    """Print application banner"""
    print(f"{Fore.CYAN}")
    print("╔═══════════════════════════════════════════════════════════╗")
    print("║         AI-Powered VAPT Agent v1.0                        ║")
    print("║         Powered by Ollama Llama 3.1                       ║")
    print("║         Clarice Systems - Agentic AI Assignment           ║")
    print("╚═══════════════════════════════════════════════════════════╝")
    print(f"{Style.RESET_ALL}\n")

def main():
    """Main execution function"""
    # Print banner
    print_banner()
    
    # Check dependencies
    print(f"{Fore.CYAN}🔍 Checking dependencies...{Style.RESET_ALL}")
    check_dependencies()
    print(f"{Fore.GREEN}✓ All dependencies installed{Style.RESET_ALL}\n")
    
    # Check Ollama
    print(f"{Fore.CYAN}🔍 Checking Ollama service...{Style.RESET_ALL}")
    check_ollama()
    print(f"{Fore.GREEN}✓ Ollama is running{Style.RESET_ALL}\n")
    
    # Import agent (after checks pass)
    try:
        from agent import VAPTAgent
    except ImportError as e:
        print(f"{Fore.RED}❌ Cannot import agent module: {e}{Style.RESET_ALL}")
        print(f"\n{Fore.YELLOW}Make sure these files exist in the same directory:{Style.RESET_ALL}")
        print("  - agent.py")
        print("  - tools.py")
        print("  - memory.py")
        print("  - planner.py")
        print("  - reporter.py")
        print("  - config.py")
        sys.exit(1)
    
    # Initialize agent
    try:
        agent = VAPTAgent()
    except Exception as e:
        print(f"{Fore.RED}❌ Failed to initialize agent: {e}{Style.RESET_ALL}")
        sys.exit(1)
    
    # Get goal and target
    if len(sys.argv) > 2:
        # Command-line arguments
        goal = sys.argv[1]
        target = sys.argv[2]
        print(f"{Fore.CYAN}Mode: Command-line{Style.RESET_ALL}")
    else:
        # Interactive input
        print(f"{Fore.CYAN}Mode: Interactive{Style.RESET_ALL}")
        print(f"\n{Fore.YELLOW}Enter scan details:{Style.RESET_ALL}")
        print(f"{Fore.WHITE}Example Goal: 'Scan for web vulnerabilities'{Style.RESET_ALL}")
        print(f"{Fore.WHITE}Example Target: 'example.com' or 'http://localhost:8000'{Style.RESET_ALL}\n")
        
        goal = input(f"{Fore.GREEN}Goal: {Style.RESET_ALL}").strip()
        target = input(f"{Fore.GREEN}Target: {Style.RESET_ALL}").strip()
        
        # Defaults if empty
        if not goal:
            goal = "Scan for web vulnerabilities"
            print(f"{Fore.YELLOW}  → Using default goal: {goal}{Style.RESET_ALL}")
        
        if not target:
            print(f"{Fore.RED}  → Target is required!{Style.RESET_ALL}")
            sys.exit(1)
    
    # Validate inputs
    if not goal or not target:
        print(f"\n{Fore.RED}❌ Both goal and target are required{Style.RESET_ALL}")
        print(f"\n{Fore.YELLOW}Usage:{Style.RESET_ALL}")
        print(f"  Interactive:  python main.py")
        print(f"  CLI:          python main.py \"<goal>\" \"<target>\"")
        print(f"\n{Fore.YELLOW}Example:{Style.RESET_ALL}")
        print(f"  python main.py \"Scan for vulnerabilities\" \"example.com\"")
        sys.exit(1)
    
    # Execute scan
    print(f"\n{Fore.CYAN}🚀 Starting security assessment...{Style.RESET_ALL}\n")
    
    try:
        agent.execute_goal(goal, target)
    except KeyboardInterrupt:
        print(f"\n\n{Fore.YELLOW}⚠️  Scan interrupted by user{Style.RESET_ALL}")
        sys.exit(0)
    except Exception as e:
        print(f"\n\n{Fore.RED}❌ Error during scan: {str(e)}{Style.RESET_ALL}")
        
        # Print traceback in debug mode
        if os.getenv("DEBUG"):
            import traceback
            traceback.print_exc()
        else:
            print(f"{Fore.YELLOW}💡 Tip: Set DEBUG=1 environment variable for detailed error info{Style.RESET_ALL}")
        
        sys.exit(1)
    
    print(f"\n{Fore.GREEN}✅ Scan completed successfully!{Style.RESET_ALL}")
    print(f"{Fore.CYAN}📁 Check the 'outputs' directory for reports{Style.RESET_ALL}\n")


if __name__ == "__main__":
    main()
