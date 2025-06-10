import os
import json
import yaml
from smolagents import CodeAgent, InferenceClientModel, DuckDuckGoSearchTool

# Import your custom security tools
from src.tools.final_answer import FinalAnswerTool
from src.tools.scan_package import ScanPackageTool
from tools.pypi_tool import PypiTool
from tools.github_tool import GithubTool
# from tools.security_summary import SecuritySummaryTool

# from Gradio_UI import GradioUI

# Get HF TOKEN for API calls
HF_TOKEN = os.getenv("HF_TOKEN")

def load_config():
    """Load agent configuration from agent.json."""
    try:
        with open("agent.json", 'r') as f:
            config = json.load(f)
        print("✅ Configuration loaded from agent.json")
        return config
    except FileNotFoundError:
        print("❌ Error: agent.json not found. Please ensure it exists in the root directory.")
        exit(1)
    except json.JSONDecodeError:
        print("❌ Error: agent.json is malformed (invalid JSON). Please check its syntax.")
        exit(1)

def load_prompts():
    """Load prompt templates from prompts.yaml."""
    try:
        with open("prompts.yaml", 'r') as f:
            prompts = yaml.safe_load(f)
        
        # Basic validation for essential keys
        if not isinstance(prompts, dict) or 'system_prompt' not in prompts:
            print("❌ Error: prompts.yaml is malformed or missing the 'system_prompt' key.")
            exit(1)
            
        print("✅ Custom prompts loaded successfully from prompts.yaml")
        return prompts
        
    except FileNotFoundError:
        print("❌ Error: prompts.yaml not found. Please ensure it exists in the root directory.")
        exit(1)
    except yaml.YAMLError as e:
        print(f"❌ Error parsing prompts.yaml: {e}. Please check its YAML syntax.")
        exit(1)

def initialize_tools():
    """Initialize all necessary tool instances for the agent."""
    print("✅ Initializing security tools...")
    tools = []
    
    # Initialize custom security tools
    tools.append(ScanPackageTool())
    print("  ✓ Vulnerability Scanner (ScanPackageTool) initialized.")
    tools.append(GithubTool())
    print("  ✓ Package Reputation Analyzer (GithubTool) initialized.")
    tools.append(PypiTool())
    print("  ✓ Dependency Chain Analyzer (PypiTool) initialized.")
    
    # Initialize general purpose tools
    tools.append(FinalAnswerTool())
    print("  ✓ Final Answer Tool initialized.")
    
    print("✅ All tools initialized.")
    return tools

def create_security_agent():
    """Create and configure the security analysis agent."""
    
    config = load_config()
    prompts = load_prompts() # Load prompts explicitly
    tools = initialize_tools()
    
    # Extract model configuration from loaded agent.json config
    model_config = config.get("model", {}).get("data", {})
    model_id = model_config.get("model_id", 'ZySec-AI/SecurityLLM') #, 'Qwen/Qwen2.5-Coder-32B-Instruct')

    model = InferenceClientModel(
        max_tokens=model_config.get("max_tokens", 3072),
        temperature=model_config.get("temperature", 0.2),
        model_id=model_id,
        custom_role_conversions=model_config.get("custom_role_conversions", None),
    )
    print(f"✅ Agent model '{model_id}' configured.")

    # Agent parameters (use values from config, or sensible defaults)
    agent_params = {
        "model": model,
        "tools": tools, # Pass the initialized tool instances
        "max_steps": config.get("max_steps", 8),
        "verbosity_level": config.get("verbosity_level", 2),
        "grammar": config.get("grammar", None),
        "planning_interval": config.get("planning_interval", 3),
        "name": config.get("name", "PythonSecurityAnalyst"),
        "description": config.get("description", "Expert cybersecurity agent for Python package security analysis"),
        "prompt_templates": prompts, # Pass the explicitly loaded prompts
    }

    agent = CodeAgent(**agent_params)
    print(" Security Analysis Agent created successfully.")
    return agent

def print_startup_info():
    """Print startup information and available capabilities."""
    print("\n" + "="*60)
    print("🔒 PYTHON SECURITY ANALYSIS ASSISTANT")
    print("="*60)
    print("\n🛡️  Available Security Analysis Capabilities:")
    print("   • Vulnerability Scanning (CVE detection)")
    print("   • Package Reputation Analysis")
    print("   • Dependency Chain Security Assessment")
    print("   • Comprehensive Security Reporting")
    print("   • General Web Search (via DuckDuckGo)")
    print("\n🔍 Example Security Tasks:")
    print("   • 'Analyze security of requests==2.25.1'")
    print("   • 'Check if flask==1.0.0 has critical vulnerabilities'")
    print("   • 'Security audit: django==2.1.0, numpy==1.19.0'")
    print("   • 'Full dependency security analysis for pandas==1.0.0'")
    print("   • 'What are the common vulnerabilities in FastAPI?'")
    print("\n🚀 Starting Gradio Interface...")
    print("="*60 + "\n")

def main():
    """Main application entry point."""
    
    # Ensure HF_TOKEN is set at the very beginning
    if not HF_TOKEN:
        print("❌ Error: HF_TOKEN environment variable not set. Please set it before running.")
        print("   Example: export HF_TOKEN='your_token_here'")
        exit(1)

    # print_startup_info()
    
    agent = create_security_agent() # This function now handles all config and tool loading

    # try:
    #     ui = GradioUI(agent)
    #     print("🌐 Launching web interface...")
    #     ui.launch(
    #         share=False, 
    #         debug=True,
    #         server_name="0.0.0.0", 
    #         server_port=7860,
    #     )
    # except Exception as e:
    #     print(f"❌ Error launching Gradio UI: {e}")
    #     print("Please ensure Gradio is installed: pip install gradio")
    #     exit(1)

    agent.run()

if __name__ == "__main__":
    main()