#!/usr/bin/env python
# coding=utf-8
# Security Analysis Gradio UI
# Based on HuggingFace smolagents Gradio implementation
# Customized for Python package security analysis

import mimetypes
import os
import re
import shutil
from typing import Optional

from smolagents.agent_types import AgentAudio, AgentImage, AgentText, handle_agent_output_types
from smolagents.agents import ActionStep, MultiStepAgent
from smolagents.memory import MemoryStep
from smolagents.utils import _is_package_available


def pull_messages_from_step(
    step_log: MemoryStep,
):
    """Extract ChatMessage objects from agent steps with proper nesting for security analysis"""
    import gradio as gr

    if isinstance(step_log, ActionStep):
        # Output the step number with security context
        step_number = f"🔍 Security Analysis Step {step_log.step_number}" if step_log.step_number is not None else "🔍 Security Analysis"
        yield gr.ChatMessage(role="assistant", content=f"**{step_number}**")

        # First yield the thought/reasoning from the security analyst LLM
        if hasattr(step_log, "model_output") and step_log.model_output is not None:
            # Clean up the LLM output
            model_output = step_log.model_output.strip()
            # Remove any trailing <end_code> and extra backticks, handling multiple possible formats
            model_output = re.sub(r"```\s*<end_code>", "```", model_output)  # handles ```<end_code>
            model_output = re.sub(r"<end_code>\s*```", "```", model_output)  # handles <end_code>```
            model_output = re.sub(r"```\s*\n\s*<end_code>", "```", model_output)  # handles ```\n<end_code>
            model_output = model_output.strip()
            yield gr.ChatMessage(role="assistant", content=model_output)

        # For security tool calls, create a parent message with security-specific icons
        if hasattr(step_log, "tool_calls") and step_log.tool_calls is not None:
            first_tool_call = step_log.tool_calls[0]
            used_code = first_tool_call.name == "python_interpreter"
            parent_id = f"call_{len(step_log.tool_calls)}"

            # Tool call becomes the parent message with timing info
            # First we will handle arguments based on type
            args = first_tool_call.arguments
            if isinstance(args, dict):
                content = str(args.get("answer", str(args)))
            else:
                content = str(args).strip()

            if used_code:
                # Clean up the content by removing any end code tags
                content = re.sub(r"```.*?\n", "", content)  # Remove existing code blocks
                content = re.sub(r"\s*<end_code>\s*", "", content)  # Remove end_code tags
                content = content.strip()
                if not content.startswith("```python"):
                    content = f"```python\n{content}\n```"

            # Security-specific tool icons
            tool_icons = {
                "vulnerability_scan": "🚨",
                "package_reputation": "📊", 
                "dependency_analysis": "🔗",
                "security_summary": "📋",
                "python_interpreter": "🐍"
            }
            tool_icon = tool_icons.get(first_tool_call.name, "🛠️")

            parent_message_tool = gr.ChatMessage(
                role="assistant",
                content=content,
                metadata={
                    "title": f"{tool_icon} Security Tool: {first_tool_call.name}",
                    "id": parent_id,
                    "status": "pending",
                },
            )
            yield parent_message_tool

            # Nesting execution logs under the tool call if they exist
            if hasattr(step_log, "observations") and (
                step_log.observations is not None and step_log.observations.strip()
            ):  # Only yield execution logs if there's actual content
                log_content = step_log.observations.strip()
                if log_content:
                    log_content = re.sub(r"^Execution logs:\s*", "", log_content)
                    yield gr.ChatMessage(
                        role="assistant",
                        content=f"{log_content}",
                        metadata={"title": "📝 Security Analysis Results", "parent_id": parent_id, "status": "done"},
                    )

            # Nesting any errors under the tool call with security context
            if hasattr(step_log, "error") and step_log.error is not None:
                yield gr.ChatMessage(
                    role="assistant",
                    content=str(step_log.error),
                    metadata={"title": "⚠️ Security Analysis Error", "parent_id": parent_id, "status": "done"},
                )

            # Update parent message metadata to done status without yielding a new message
            parent_message_tool.metadata["status"] = "done"

        # Handle standalone errors but not from tool calls
        elif hasattr(step_log, "error") and step_log.error is not None:
            yield gr.ChatMessage(role="assistant", content=str(step_log.error), metadata={"title": "⚠️ Analysis Error"})

        # Calculate duration and token information
        step_footnote = f"{step_number.replace('**', '')}"
        if hasattr(step_log, "input_token_count") and hasattr(step_log, "output_token_count"):
            token_str = (
                f" | Input-tokens:{step_log.input_token_count:,} | Output-tokens:{step_log.output_token_count:,}"
            )
            step_footnote += token_str
        if hasattr(step_log, "duration"):
            step_duration = f" | Duration: {round(float(step_log.duration), 2)}s" if step_log.duration else None
            step_footnote += step_duration
        step_footnote = f"""<span style="color: #bbbbc2; font-size: 12px;">{step_footnote}</span> """
        yield gr.ChatMessage(role="assistant", content=f"{step_footnote}")
        yield gr.ChatMessage(role="assistant", content="---")


def stream_to_gradio(
    agent,
    task: str,
    reset_agent_memory: bool = False,
    additional_args: Optional[dict] = None,
):
    """Runs a security agent with the given task and streams the messages as gradio ChatMessages."""
    if not _is_package_available("gradio"):
        raise ModuleNotFoundError(
            "Please install 'gradio' extra to use the GradioUI: `pip install 'smolagents[gradio]'`"
        )
    import gradio as gr

    total_input_tokens = 0
    total_output_tokens = 0

    for step_log in agent.run(task, stream=True, reset=reset_agent_memory, additional_args=additional_args):
        # Track tokens if model provides them
        if hasattr(agent.model, "last_input_token_count"):
            total_input_tokens += agent.model.last_input_token_count
            total_output_tokens += agent.model.last_output_token_count
            if isinstance(step_log, ActionStep):
                step_log.input_token_count = agent.model.last_input_token_count
                step_log.output_token_count = agent.model.last_output_token_count

        for message in pull_messages_from_step(
            step_log,
        ):
            yield message

    final_answer = step_log  # Last log is the run's final_answer
    final_answer = handle_agent_output_types(final_answer)

    if isinstance(final_answer, AgentText):
        yield gr.ChatMessage(
            role="assistant",
            content=f"🔒 **Security Analysis Report:**\n{final_answer.to_string()}\n",
        )
    elif isinstance(final_answer, AgentImage):
        yield gr.ChatMessage(
            role="assistant",
            content={"path": final_answer.to_string(), "mime_type": "image/png"},
        )
    elif isinstance(final_answer, AgentAudio):
        yield gr.ChatMessage(
            role="assistant",
            content={"path": final_answer.to_string(), "mime_type": "audio/wav"},
        )
    else:
        yield gr.ChatMessage(role="assistant", content=f"🔒 **Security Analysis Complete:** {str(final_answer)}")


class GradioUI:
    """Security Analysis Gradio Interface - One-line interface to launch your security agent in Gradio"""

    def __init__(self, agent: MultiStepAgent, file_upload_folder: str | None = None):
        if not _is_package_available("gradio"):
            raise ModuleNotFoundError(
                "Please install 'gradio' extra to use the GradioUI: `pip install 'smolagents[gradio]'`"
            )
        self.agent = agent
        self.file_upload_folder = file_upload_folder or "./uploads"
        if not os.path.exists(self.file_upload_folder):
            os.makedirs(self.file_upload_folder, exist_ok=True)

    def interact_with_agent(self, prompt, messages):
        """FIXED: Simplified interaction handling"""
        import gradio as gr

        messages.append(gr.ChatMessage(role="user", content=prompt))
        yield messages
        for msg in stream_to_gradio(self.agent, task=prompt, reset_agent_memory=False):
            messages.append(msg)
            yield messages
        yield messages

    def upload_file(
        self,
        file,
        file_uploads_log,
        allowed_file_types=[
            "text/plain",  # requirements.txt, setup.py, etc.
            "application/x-python-code",  # .py files
            "text/x-python",  # .py files alternative
            "application/toml",  # pyproject.toml
            "text/x-yaml",  # .yml/.yaml files
            "application/x-yaml",  # .yml/.yaml files alternative
            "application/json",  # .json files
            "text/csv",  # .csv files for dependency lists
        ],
    ):
        """Handle security-related file uploads"""
        import gradio as gr

        if file is None:
            return gr.Textbox("No file uploaded", visible=True), file_uploads_log

        try:
            mime_type, _ = mimetypes.guess_type(file.name)
            # Handle common security file extensions that might not have proper mime types
            file_ext = os.path.splitext(file.name)[1].lower()
            if file_ext in ['.txt', '.py', '.toml', '.yml', '.yaml', '.json', '.csv']:
                # Allow these common security analysis file types
                if mime_type is None:
                    if file_ext == '.txt':
                        mime_type = "text/plain"
                    elif file_ext == '.py':
                        mime_type = "text/x-python"
                    elif file_ext == '.toml':
                        mime_type = "application/toml"
                    elif file_ext in ['.yml', '.yaml']:
                        mime_type = "text/x-yaml"
                    elif file_ext == '.json':
                        mime_type = "application/json"
                    elif file_ext == '.csv':
                        mime_type = "text/csv"
        except Exception as e:
            return gr.Textbox(f"Error determining file type: {e}", visible=True), file_uploads_log

        if mime_type not in allowed_file_types:
            allowed_extensions = ['.txt', '.py', '.toml', '.yml', '.yaml', '.json', '.csv']
            return gr.Textbox(
                f"File type not allowed for security analysis. Allowed types: {', '.join(allowed_extensions)}", 
                visible=True
            ), file_uploads_log

        # Sanitize file name
        original_name = os.path.basename(file.name)
        sanitized_name = re.sub(
            r"[^\w\-.]", "_", original_name
        )  # Replace any non-alphanumeric, non-dash, or non-dot characters with underscores

        # Save the uploaded file to the specified folder
        file_path = os.path.join(self.file_upload_folder, sanitized_name)
        shutil.copy(file.name, file_path)

        return gr.Textbox(f"✅ Security file uploaded: {file_path}", visible=True), file_uploads_log + [file_path]

    def log_user_message(self, text_input, file_uploads_log):
        """FIXED: Simplified message logging"""
        enhanced_message = text_input
        if len(file_uploads_log) > 0:
            enhanced_message += f"\n\n📁 **Uploaded Files for Analysis:** {', '.join(file_uploads_log)}"
        
        return enhanced_message, ""  # Return enhanced message and clear input

    def launch(self, **kwargs):
        import gradio as gr

        # Security-themed CSS
        css = """
        .security-header {
            background: linear-gradient(90deg, #1e3a8a 0%, #3b82f6 100%);
            color: white;
            padding: 1rem;
            border-radius: 8px;
            margin-bottom: 1rem;
            text-align: center;
        }
        .security-info {
            background: #304552;
            border: 1px solid #0284c7;
            border-radius: 6px;
            padding: 0.75rem;
            margin: 0.5rem 0;
        }
        .example-button {
            margin: 0.2rem;
            background: #304552 !important;
            border: 1px solid #0284c7 !important;
        }
        """

        with gr.Blocks(fill_height=True, css=css, title="🔒 Python Security Analysis Assistant") as demo:
            stored_messages = gr.State([])
            file_uploads_log = gr.State([])
            
            # Security-themed header
            gr.HTML("""
                <div class="security-header">
                    <h1>🔒 Python Security Analysis Assistant</h1>
                    <p>Comprehensive security analysis for Python packages and dependencies</p>
                </div>
            """)
            
            # Security capabilities info
            with gr.Row():
                gr.HTML("""
                    <div class="security-info">
                        <h3>🛡️ Security Analysis Capabilities:</h3>
                        <ul>
                            <li><strong>Vulnerability Scanning:</strong> CVE detection and CVSS scoring</li>
                            <li><strong>Package Reputation:</strong> Trust and maintenance analysis</li>
                            <li><strong>Dependency Analysis:</strong> Supply chain security assessment</li>
                            <li><strong>Security Reporting:</strong> Executive summaries and remediation plans</li>
                        </ul>
                    </div>
                """)
            
            chatbot = gr.Chatbot(
                label="🔒 Security Analyst",
                type="messages",
                avatar_images=(
                    None,
                    "https://raw.githubusercontent.com/microsoft/fluentui-emoji/main/assets/Shield/3D/shield_3d.png",
                ),
                resizeable=True,
                scale=1,
                height=400,
            )
            
            with gr.Row():
                with gr.Column(scale=4):
                    text_input = gr.Textbox(
                        lines=1,  # FIXED: Back to single line like HF version
                        label="🔍 Security Analysis Request",
                        placeholder="Ask me to analyze package security, check for vulnerabilities, or audit dependencies..."
                    )
                
                with gr.Column(scale=1):
                    # Security file upload
                    upload_file = gr.File(
                        label="📁 Upload Security Files",
                        file_types=[".txt", ".py", ".toml", ".yml", ".yaml", ".json", ".csv"]
                    )
            
            upload_status = gr.Textbox(label="📤 Upload Status", interactive=False, visible=False)
            
            # Example security tasks
            with gr.Row():
                with gr.Column():
                    gr.HTML("<h4>💡 Example Security Analysis Tasks:</h4>")
                    example_1 = gr.Button("🔍 Analyze security of requests==2.25.1", elem_classes=["example-button"])
                    example_2 = gr.Button("🚨 Check for critical vulnerabilities in flask==1.0.0", elem_classes=["example-button"])
                    example_3 = gr.Button("📊 Security audit: django==2.1.0, numpy==1.19.0", elem_classes=["example-button"])
                    example_4 = gr.Button("🔗 Full dependency security analysis for fastapi==0.68.0", elem_classes=["example-button"])
            # <div id="component-15" class="row svelte-1xp0cw7 unequal-height"> </div>
            # FIXED: Event handlers - simplified like HF version
            upload_file.change(
                self.upload_file,
                [upload_file, file_uploads_log],
                [upload_status, file_uploads_log],
            )
            
            # FIXED: Direct connection like HF version
            text_input.submit(
                self.log_user_message,
                [text_input, file_uploads_log],
                [stored_messages, text_input],
            ).then(self.interact_with_agent, [stored_messages, chatbot], [chatbot])
            
            # Example button handlers
            def handle_example(example_text):
                return example_text
            
            example_1.click(
                lambda: "Analyze security of requests==2.25.1",
                outputs=[text_input]
            )
            example_2.click(
                lambda: "Check for critical vulnerabilities in flask==1.0.0",
                outputs=[text_input]
            )
            example_3.click(
                lambda: "Security audit: django==2.1.0, numpy==1.19.0",
                outputs=[text_input]
            )
            example_4.click(
                lambda: "Full dependency security analysis for fastapi==0.68.0",
                outputs=[text_input]
            )

        # Set default launch parameters for security context
        launch_kwargs = {
            "debug": True,
            "share": False,  # Keep secure by default
            "server_name": "127.0.0.1",  # Local only by default
            "server_port": 7860,
            **kwargs
        }
        
        demo.launch(**launch_kwargs)


__all__ = ["stream_to_gradio", "GradioUI"]