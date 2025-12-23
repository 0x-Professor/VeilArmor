"""Veil Armor Secure Chat - Research Edition
Professional interface for LLM security research.
"""
import streamlit as st
import torch
from transformers import AutoTokenizer, AutoModelForCausalLM, TextIteratorStreamer
from threading import Thread
import time
import os
from dotenv import load_dotenv

# Import security
from security_client import SecurityPipeline

load_dotenv()

# ========================
# Configuration
# ========================
MODEL_NAME = "huihui-ai/Qwen2.5-3B-Instruct-abliterated"
API_URL = os.getenv("VEIL_ARMOR_API_URL", "http://localhost:8000")
HF_TOKEN = os.getenv("HF_TOKEN", "")

# ========================
# Page Setup
# ========================
st.set_page_config(
    page_title="Veil Armor",
    page_icon="VA",
    layout="wide",
    initial_sidebar_state="collapsed"
)

# Professional Research UI CSS
st.markdown("""
<style>
    @import url('https://fonts.googleapis.com/css2?family=IBM+Plex+Sans:wght@400;500;600&family=IBM+Plex+Mono:wght@400;500&display=swap');
    
    :root {
        --bg-primary: #09090b;
        --bg-secondary: #18181b;
        --bg-tertiary: #27272a;
        --border-color: #3f3f46;
        --text-primary: #fafafa;
        --text-secondary: #a1a1aa;
        --text-muted: #71717a;
        --accent-primary: #6366f1;
        --accent-secondary: #818cf8;
        --success: #22c55e;
        --warning: #eab308;
        --error: #ef4444;
    }
    
    #MainMenu, footer, header, .stDeployButton {display: none !important;}
    
    .stApp {
        background: var(--bg-primary) !important;
        font-family: 'IBM Plex Sans', -apple-system, BlinkMacSystemFont, sans-serif !important;
    }
    
    .main .block-container {
        padding: 0 !important;
        max-width: 100% !important;
    }
    
    /* Top Navigation Bar */
    .nav-bar {
        position: fixed;
        top: 0;
        left: 0;
        right: 0;
        height: 56px;
        background: var(--bg-secondary);
        border-bottom: 1px solid var(--border-color);
        display: flex;
        align-items: center;
        justify-content: space-between;
        padding: 0 24px;
        z-index: 1000;
    }
    
    .nav-brand {
        display: flex;
        align-items: center;
        gap: 12px;
    }
    
    .nav-logo {
        width: 32px;
        height: 32px;
        background: var(--accent-primary);
        border-radius: 8px;
        display: flex;
        align-items: center;
        justify-content: center;
    }
    
    .nav-logo svg {
        width: 18px;
        height: 18px;
    }
    
    .nav-title {
        font-size: 16px;
        font-weight: 600;
        color: var(--text-primary);
        letter-spacing: -0.3px;
    }
    
    .nav-status {
        display: flex;
        align-items: center;
        gap: 20px;
    }
    
    .status-indicator {
        display: flex;
        align-items: center;
        gap: 8px;
        font-size: 13px;
        color: var(--text-secondary);
    }
    
    .status-dot {
        width: 6px;
        height: 6px;
        border-radius: 50%;
    }
    
    .status-dot.active { background: var(--success); }
    .status-dot.inactive { background: var(--error); }
    
    .nav-actions {
        display: flex;
        align-items: center;
        gap: 12px;
    }
    
    .nav-btn {
        padding: 6px 12px;
        background: transparent;
        border: 1px solid var(--border-color);
        border-radius: 6px;
        color: var(--text-secondary);
        font-size: 13px;
        font-weight: 500;
        cursor: pointer;
        transition: all 0.15s ease;
    }
    
    .nav-btn:hover {
        background: var(--bg-tertiary);
        color: var(--text-primary);
    }
    
    /* Main Content Area */
    .content-wrapper {
        margin-top: 56px;
        height: calc(100vh - 56px);
        display: flex;
        flex-direction: column;
    }
    
    /* Welcome State */
    .welcome-container {
        flex: 1;
        display: flex;
        flex-direction: column;
        align-items: center;
        justify-content: center;
        padding: 48px 24px;
    }
    
    .welcome-icon {
        width: 72px;
        height: 72px;
        background: linear-gradient(135deg, var(--accent-primary), var(--accent-secondary));
        border-radius: 16px;
        display: flex;
        align-items: center;
        justify-content: center;
        margin-bottom: 24px;
    }
    
    .welcome-icon svg {
        width: 36px;
        height: 36px;
    }
    
    .welcome-title {
        font-size: 28px;
        font-weight: 600;
        color: var(--text-primary);
        margin-bottom: 8px;
        letter-spacing: -0.5px;
    }
    
    .welcome-subtitle {
        font-size: 15px;
        color: var(--text-muted);
        margin-bottom: 32px;
    }
    
    .feature-grid {
        display: grid;
        grid-template-columns: repeat(3, 1fr);
        gap: 12px;
        max-width: 600px;
        width: 100%;
    }
    
    .feature-card {
        padding: 16px;
        background: var(--bg-secondary);
        border: 1px solid var(--border-color);
        border-radius: 10px;
        text-align: center;
    }
    
    .feature-card-title {
        font-size: 13px;
        font-weight: 500;
        color: var(--text-primary);
        margin-bottom: 4px;
    }
    
    .feature-card-desc {
        font-size: 12px;
        color: var(--text-muted);
    }
    
    /* Chat Styles */
    .stChatMessage {
        background: transparent !important;
        padding: 0 !important;
        max-width: 800px;
        margin: 0 auto;
    }
    
    [data-testid="stChatMessageContent"] {
        background: var(--bg-secondary) !important;
        border: 1px solid var(--border-color) !important;
        border-radius: 12px !important;
        padding: 16px !important;
        font-family: 'IBM Plex Sans', sans-serif !important;
        font-size: 14px !important;
        line-height: 1.6 !important;
        color: var(--text-primary) !important;
    }
    
    [data-testid="stChatMessageContent"] p {
        color: var(--text-primary) !important;
        margin: 0 !important;
    }
    
    [data-testid="stChatMessageAvatarUser"] {
        background: var(--accent-primary) !important;
        border-radius: 8px !important;
    }
    
    [data-testid="stChatMessageAvatarAssistant"] {
        background: var(--bg-tertiary) !important;
        border: 1px solid var(--border-color) !important;
        border-radius: 8px !important;
    }
    
    /* Chat Input - Dark Theme */
    .stChatInput,
    [data-testid="stChatInput"],
    .stChatInputContainer {
        position: fixed !important;
        bottom: 0 !important;
        left: 0 !important;
        right: 0 !important;
        background: #09090b !important;
        padding: 16px 24px 20px 24px !important;
        z-index: 999 !important;
        border-top: 1px solid #27272a !important;
    }
    
    .stChatInput > div,
    [data-testid="stChatInput"] > div,
    .stChatInput [data-baseweb="textarea"],
    [data-testid="stChatInputTextArea"],
    .stChatInput div[data-baseweb] {
        background: #18181b !important;
        border: 1px solid #3f3f46 !important;
        border-radius: 24px !important;
    }
    
    .stChatInput textarea,
    [data-testid="stChatInput"] textarea,
    .stChatInput input,
    [data-testid="stChatInputTextArea"] textarea {
        background: #18181b !important;
        background-color: #18181b !important;
        color: #fafafa !important;
        font-family: 'IBM Plex Sans', sans-serif !important;
        font-size: 15px !important;
        caret-color: #fafafa !important;
        border: none !important;
        border-radius: 24px !important;
    }
    
    .stChatInput textarea::placeholder,
    [data-testid="stChatInput"] textarea::placeholder {
        color: #71717a !important;
    }
    
    /* Send button */
    .stChatInput button,
    [data-testid="stChatInput"] button {
        background: #6366f1 !important;
        border: none !important;
        border-radius: 50% !important;
    }
    
    .stChatInput button:hover,
    [data-testid="stChatInput"] button:hover {
        background: #818cf8 !important;
    }
    
    /* Force dark background on all input elements */
    .stChatInput *,
    [data-testid="stChatInput"] * {
        background-color: transparent !important;
    }
    
    .stChatInput > div > div,
    [data-testid="stChatInput"] > div > div {
        background: #18181b !important;
    }
    
    /* Bottom padding for content */
    .main .block-container {
        padding-bottom: 100px !important;
    }
    
    /* Remove any white backgrounds */
    .stTextInput > div > div,
    [data-baseweb="input"],
    [data-baseweb="textarea"] {
        background: #18181b !important;
        border-color: #3f3f46 !important;
    }
    
    /* Security Status Badge */
    .security-status {
        display: inline-flex;
        align-items: center;
        gap: 6px;
        padding: 4px 10px;
        background: rgba(34, 197, 94, 0.1);
        border: 1px solid rgba(34, 197, 94, 0.2);
        border-radius: 6px;
        font-size: 12px;
        font-family: 'IBM Plex Mono', monospace;
        color: var(--success);
        margin-top: 8px;
    }
    
    .security-status.warning {
        background: rgba(234, 179, 8, 0.1);
        border-color: rgba(234, 179, 8, 0.2);
        color: var(--warning);
    }
    
    .security-status.error {
        background: rgba(239, 68, 68, 0.1);
        border-color: rgba(239, 68, 68, 0.2);
        color: var(--error);
    }
    
    /* Streamlit Overrides */
    .stButton > button {
        background: var(--bg-secondary) !important;
        border: 1px solid var(--border-color) !important;
        border-radius: 8px !important;
        color: var(--text-secondary) !important;
        font-family: 'IBM Plex Sans', sans-serif !important;
        font-size: 13px !important;
        font-weight: 500 !important;
        padding: 8px 16px !important;
        transition: all 0.15s ease !important;
    }
    
    .stButton > button:hover {
        background: var(--bg-tertiary) !important;
        border-color: var(--text-muted) !important;
        color: var(--text-primary) !important;
    }
    
    .stCaption {
        font-family: 'IBM Plex Mono', monospace !important;
        font-size: 12px !important;
        color: var(--text-muted) !important;
    }
    
    .stMarkdown {
        color: var(--text-primary) !important;
    }
    
    .stError {
        background: rgba(239, 68, 68, 0.1) !important;
        border: 1px solid rgba(239, 68, 68, 0.2) !important;
        border-radius: 8px !important;
        color: var(--error) !important;
    }
    
    /* Scrollbar */
    ::-webkit-scrollbar {
        width: 8px;
        height: 8px;
    }
    
    ::-webkit-scrollbar-track {
        background: var(--bg-primary);
    }
    
    ::-webkit-scrollbar-thumb {
        background: var(--border-color);
        border-radius: 4px;
    }
    
    ::-webkit-scrollbar-thumb:hover {
        background: var(--text-muted);
    }
</style>
""", unsafe_allow_html=True)


# ========================
# Model Loading
# ========================
@st.cache_resource
def load_model():
    """Load model and tokenizer."""
    try:
        tokenizer = AutoTokenizer.from_pretrained(
            MODEL_NAME,
            trust_remote_code=True,
            token=HF_TOKEN if HF_TOKEN else None
        )
        
        device = "cuda" if torch.cuda.is_available() else "cpu"
        dtype = torch.float16 if device == "cuda" else torch.float32
        
        model = AutoModelForCausalLM.from_pretrained(
            MODEL_NAME,
            torch_dtype=dtype,
            device_map="auto" if device == "cuda" else None,
            trust_remote_code=True,
            token=HF_TOKEN if HF_TOKEN else None
        )
        
        if device == "cpu":
            model = model.to(device)
        
        return tokenizer, model, device
    except Exception as e:
        st.error(f"Model loading failed: {e}")
        return None, None, None


@st.cache_resource
def load_security():
    """Load security pipeline."""
    return SecurityPipeline(api_url=API_URL)


# ========================
# Streaming Generation
# ========================
def generate_stream(tokenizer, model, device, messages, max_tokens=512, temperature=0.7):
    """Generate response with streaming."""
    try:
        inputs = tokenizer.apply_chat_template(
            messages,
            add_generation_prompt=True,
            tokenize=True,
            return_dict=True,
            return_tensors="pt"
        ).to(device)
        
        streamer = TextIteratorStreamer(
            tokenizer,
            skip_prompt=True,
            skip_special_tokens=True
        )
        
        generation_kwargs = {
            **inputs,
            "max_new_tokens": max_tokens,
            "temperature": temperature,
            "do_sample": True,
            "top_p": 0.9,
            "streamer": streamer,
            "pad_token_id": tokenizer.eos_token_id
        }
        
        thread = Thread(target=model.generate, kwargs=generation_kwargs)
        thread.start()
        
        return streamer
        
    except Exception as e:
        return None


# ========================
# Main App
# ========================
def main():
    # Initialize
    if "messages" not in st.session_state:
        st.session_state.messages = []
    if "stats" not in st.session_state:
        st.session_state.stats = {
            "total": 0, "blocked": 0, "sanitized": 0, "clean": 0
        }
    
    # Load resources
    tokenizer, model, device = load_model()
    security = load_security()
    api_online = security.is_api_available() if security else False
    
    # Render navigation bar
    api_status = "active" if api_online else "inactive"
    model_status = "active" if model else "inactive"
    device_name = device.upper() if device else "N/A"
    
    st.markdown(f"""
    <div class="nav-bar">
        <div class="nav-brand">
            <div class="nav-logo">
                <svg viewBox="0 0 24 24" fill="white">
                    <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
                </svg>
            </div>
            <span class="nav-title">Veil Armor</span>
        </div>
        <div class="nav-status">
            <div class="status-indicator">
                <span class="status-dot {api_status}"></span>
                Security API
            </div>
            <div class="status-indicator">
                <span class="status-dot {model_status}"></span>
                Model ({device_name})
            </div>
        </div>
        <div class="nav-actions">
            <span style="font-size: 12px; color: var(--text-muted);">
                Session: {st.session_state.stats['total']} queries
            </span>
        </div>
    </div>
    <div class="content-wrapper">
    """, unsafe_allow_html=True)
    
    # Check model
    if not model:
        st.error("Model initialization failed. Check configuration and restart.")
        return
    
    # Welcome state (no messages)
    if not st.session_state.messages:
        st.markdown("""
        <div class="welcome-container">
            <div class="welcome-icon">
                <svg viewBox="0 0 24 24" fill="white">
                    <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
                </svg>
            </div>
            <div class="welcome-title">Veil Armor</div>
            <div class="welcome-subtitle">Secure LLM Interface with Real-time Threat Detection</div>
            <div class="feature-grid">
                <div class="feature-card">
                    <div class="feature-card-title">Input Scanning</div>
                    <div class="feature-card-desc">Prompt injection detection</div>
                </div>
                <div class="feature-card">
                    <div class="feature-card-title">PII Protection</div>
                    <div class="feature-card-desc">Automatic data redaction</div>
                </div>
                <div class="feature-card">
                    <div class="feature-card-title">Output Filtering</div>
                    <div class="feature-card-desc">Response sanitization</div>
                </div>
            </div>
        </div>
        """, unsafe_allow_html=True)
    
    # Chat history
    for msg in st.session_state.messages:
        with st.chat_message(msg["role"]):
            st.markdown(msg["content"])
            if "security" in msg and msg["role"] == "assistant":
                sec = msg["security"]
                if sec.get("input_action") == "block":
                    st.markdown('<div class="security-status error">BLOCKED</div>', unsafe_allow_html=True)
                elif sec.get("input_action") == "redact":
                    st.markdown(f'<div class="security-status warning">REDACTED: {sec.get("pii_count", 0)} items</div>', unsafe_allow_html=True)
                elif sec.get("output_redacted", 0) > 0:
                    st.markdown('<div class="security-status warning">FILTERED</div>', unsafe_allow_html=True)
                else:
                    st.markdown('<div class="security-status">VERIFIED</div>', unsafe_allow_html=True)
    
    st.markdown("</div>", unsafe_allow_html=True)
    
    # Chat input
    if prompt := st.chat_input("Enter your query..."):
        st.session_state.stats["total"] += 1
        
        security_info = {}
        processed_prompt = prompt
        
        if security and api_online:
            should_continue, processed_prompt, input_sec = security.process_input(prompt)
            security_info["input_action"] = input_sec.get("action", "allow")
            security_info["pii_count"] = input_sec.get("pii_count", 0)
            
            if not should_continue:
                st.session_state.stats["blocked"] += 1
                
                with st.chat_message("user"):
                    st.markdown("[Content blocked]")
                
                with st.chat_message("assistant"):
                    st.markdown("Request blocked. Security scan detected potential threats including prompt injection, jailbreak patterns, or sensitive data. Modify your input and retry.")
                    st.markdown('<div class="security-status error">BLOCKED</div>', unsafe_allow_html=True)
                
                st.session_state.messages.append({
                    "role": "user",
                    "content": "[Blocked by security]"
                })
                st.session_state.messages.append({
                    "role": "assistant",
                    "content": "Request blocked due to security policy.",
                    "security": security_info
                })
                st.rerun()
                return
            
            if input_sec.get("action") == "redact":
                st.session_state.stats["sanitized"] += 1
        
        with st.chat_message("user"):
            st.markdown(prompt)
        st.session_state.messages.append({"role": "user", "content": processed_prompt})
        
        with st.chat_message("assistant"):
            model_messages = [
                {"role": m["role"], "content": m["content"]}
                for m in st.session_state.messages[:-1]
            ]
            model_messages.append({"role": "user", "content": processed_prompt})
            
            placeholder = st.empty()
            full_response = ""
            
            streamer = generate_stream(
                tokenizer, model, device, model_messages,
                max_tokens=512, temperature=0.7
            )
            
            if streamer:
                for chunk in streamer:
                    full_response += chunk
                    placeholder.markdown(full_response + "...")
                placeholder.markdown(full_response)
            else:
                full_response = "Generation failed. Please try again."
                placeholder.markdown(full_response)
            
            if security and api_online and full_response:
                safe_response, output_sec = security.process_output(full_response)
                security_info["output_redacted"] = output_sec.get("pii_redacted", 0)
                
                if safe_response != full_response:
                    placeholder.markdown(safe_response)
                    full_response = safe_response
            
            if security_info.get("input_action") == "redact":
                st.markdown(f'<div class="security-status warning">REDACTED: {security_info.get("pii_count", 0)} items</div>', unsafe_allow_html=True)
            elif security_info.get("output_redacted", 0) > 0:
                st.markdown('<div class="security-status warning">FILTERED</div>', unsafe_allow_html=True)
            else:
                st.markdown('<div class="security-status">VERIFIED</div>', unsafe_allow_html=True)
                st.session_state.stats["clean"] += 1
        
        st.session_state.messages.append({
            "role": "assistant",
            "content": full_response,
            "security": security_info
        })
    
    # Clear button
    if st.session_state.messages:
        col1, col2, col3 = st.columns([2, 1, 2])
        with col2:
            if st.button("Clear Session", use_container_width=True):
                st.session_state.messages = []
                st.session_state.stats = {"total": 0, "blocked": 0, "sanitized": 0, "clean": 0}
                st.rerun()


if __name__ == "__main__":
    main()
