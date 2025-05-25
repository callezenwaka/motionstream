import os
import json
import yaml
from smolagents import CodeAgent, InferenceClientModel, DuckDuckGoSearchTool

# Import our custom security tools
from tools.vulnerability_scan import ScanTool
from tools.package_reputation import ReputationTool
from tools.dependency_chain import DependencyChainTool
from tools.security_summary import SecuritySummaryTool
from tools.final_answer import FinalAnswerTool

from Gradio_UI import GradioUI

# Get HF TOKEN for API calls
HF_TOKEN = os.getenv("HF_TOKEN")

def load_config():
    """Load agent configuration from agent.json"""
    try:
        with open("agent.json", 'r') as f:
            config = json.load(f)
        return config
    except FileNotFoundError:
        print("Warning: agent.json not found, using default configuration")
        return None

def load_prompts():
    """Load prompt templates from prompts.yaml"""
    try:
        with open("prompts.yaml", 'r') as f:
            prompts = yaml.safe_load(f)
        
        # Validate prompt structure
        if not isinstance(prompts, dict):
            print("Warning: prompts.yaml did not load as dictionary, skipping custom prompts")
            return None
            
        # Ensure required templates exist
        required_templates = ['system_prompt']
        for template in required_templates:
            if template not in prompts:
                print(f"Warning: Required template '{template}' missing from prompts.yaml")
                return None
        
        print("✅ Custom prompts loaded successfully")
        return prompts
        
    except FileNotFoundError:
        print("Warning: prompts.yaml not found, using default prompts")
        return None
    except yaml.YAMLError as e:
        print(f"Warning: Error parsing prompts.yaml: {e}, using default prompts")
        return None
    except Exception as e:
        print(f"Warning: Unexpected error loading prompts: {e}, using default prompts")
        return None

def initialize_security_tools():
    """Initialize all security analysis tools"""
    tools = []
    
    try:
        # Initialize vulnerability scanning tool
        vulnerability_scanner = ScanTool()
        tools.append(vulnerability_scanner)
        print("✅ Vulnerability Scanner initialized")
        
        # Initialize package reputation tool
        reputation_analyzer = ReputationTool()
        tools.append(reputation_analyzer)
        print("✅ Package Reputation Analyzer initialized")
        
        # Initialize dependency chain tool
        dependency_analyzer = DependencyChainTool()
        tools.append(dependency_analyzer)
        print("✅ Dependency Chain Analyzer initialized")
        
        # Initialize security summary tool
        security_summarizer = SecuritySummaryTool()
        tools.append(security_summarizer)
        print("✅ Security Report Generator initialized")
        
        # Add final answer tool
        final_answer = FinalAnswerTool()
        tools.append(final_answer)
        print("✅ Final Answer Tool initialized")
        
        return tools
        
    except Exception as e:
        print(f"❌ Error initializing security tools: {e}")
        # Fallback to just final answer if tools fail
        return [FinalAnswerTool()]

def create_security_agent():
    """Create and configure the security analysis agent"""
    
    # Load configuration
    config = load_config()
    prompts = load_prompts()
    
    # Initialize security tools
    security_tools = initialize_security_tools()
    
    # Configure model from agent.json or use defaults
    if config and "model" in config:
        model_config = config["model"]["data"]
        model = InferenceClientModel(
            max_tokens=model_config.get("max_tokens", 3072),
            temperature=model_config.get("temperature", 0.2),
            model_id=model_config.get("model_id", 'Qwen/Qwen2.5-Coder-32B-Instruct'),
            custom_role_conversions=model_config.get("custom_role_conversions", None),
        )
    else:
        # Fallback model configuration optimized for security analysis
        model = InferenceClientModel(
            max_tokens=3072,
            temperature=0.2,
            model_id='Qwen/Qwen2.5-Coder-32B-Instruct',
            custom_role_conversions=None,
        )
    
    # Configure agent parameters from agent.json or use defaults
    if config:
        agent_params = {
            "model": model,
            "tools": security_tools,
            "max_steps": config.get("max_steps", 8),
            "verbosity_level": config.get("verbosity_level", 2),
            "grammar": config.get("grammar", None),
            "planning_interval": config.get("planning_interval", 3),
            "name": config.get("name", "PythonSecurityAnalyst"),
            "description": config.get("description", "Expert cybersecurity agent for Python package security analysis"),
        }
    else:
        agent_params = {
            "model": model,
            "tools": security_tools,
            "max_steps": 8,
            "verbosity_level": 2,
            "grammar": None,
            "planning_interval": 3,
            "name": "PythonSecurityAnalyst",
            "description": "Expert cybersecurity agent for Python package security analysis",
        }
    
    # Add prompt templates if available and valid
    if prompts and isinstance(prompts, dict):
        try:
            agent_params["prompt_templates"] = prompts
            print("✅ Using custom security prompts")
        except Exception as e:
            print(f"Warning: Error applying custom prompts: {e}")
            print("Continuing with default prompts...")
    else:
        print("ℹ️ Using default prompts")
    
    # Create the security analysis agent
    try:
        agent = CodeAgent(**agent_params)
        print("✅ Security Analysis Agent created successfully")
        return agent
    except Exception as e:
        print(f"❌ Error creating agent with custom config: {e}")
        print("🔄 Trying with minimal configuration...")
        
        # Create minimal agent as fallback
        try:
            minimal_agent = CodeAgent(
                model=model,
                tools=security_tools,
                max_steps=6,
                verbosity_level=1,
            )
            print("✅ Minimal Security Agent created successfully")
            return minimal_agent
        except Exception as e2:
            print(f"❌ Error creating minimal agent: {e2}")
            # Last resort - just final answer tool
            final_answer_tool = FinalAnswerTool()
            return CodeAgent(
                model=model,
                tools=[final_answer_tool, DuckDuckGoSearchTool],
                max_steps=4,
                verbosity_level=1,
            )

def print_startup_info():
    """Print startup information and available capabilities"""
    print("\n" + "="*60)
    print("🔒 PYTHON SECURITY ANALYSIS ASSISTANT")
    print("="*60)
    print("\n🛡️  Available Security Analysis Capabilities:")
    print("   • Vulnerability Scanning (CVE detection)")
    print("   • Package Reputation Analysis")
    print("   • Dependency Chain Security Assessment")
    print("   • Comprehensive Security Reporting")
    print("\n🔍 Example Security Tasks:")
    print("   • 'Analyze security of requests==2.25.1'")
    print("   • 'Check if flask==1.0.0 has critical vulnerabilities'")
    print("   • 'Security audit: django==2.1.0, numpy==1.19.0'")
    print("   • 'Full dependency security analysis for pandas==1.0.0'")
    print("\n🚀 Starting Gradio Interface...")
    print("="*60 + "\n")

def main():
    """Main application entry point"""
    
    # Print startup information
    print_startup_info()
    
    # Create the security analysis agent
    agent = create_security_agent()
    
    # Launch the Gradio UI
    try:
        ui = GradioUI(agent)
        print("🌐 Launching web interface...")
        ui.launch(
            share=False,  # Set to True if you want to share publicly
            debug=True,   # Enable debug mode for development
            server_name="127.0.0.1",  # Local access only
            server_port=7860,  # Default Gradio port
        )
    except Exception as e:
        print(f"❌ Error launching Gradio UI: {e}")
        print("Please check your Gradio installation and try again.")

if __name__ == "__main__":
    # Ensure required environment variables are set
    if not HF_TOKEN:
        print("⚠️  Warning: HF_TOKEN environment variable not set.")
        print("   Some features may not work properly.")
        print("   Please set your Hugging Face token: export HF_TOKEN='your_token_here'")
    
    # Run the application  
    main()