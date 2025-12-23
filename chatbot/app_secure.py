"""Veil Armor Secure Chat - Professional Edition
Clean, minimal dashboard with streaming responses.
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

# Professional Dark Theme CSS (Grok-style)
st.markdown("""
<style>
    /* Import font */
    @import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&display=swap');
    
    /* Hide Streamlit branding */
    #MainMenu {visibility: hidden;}
    footer {visibility: hidden;}
    header {visibility: hidden;}
    .stDeployButton {display: none;}
    
    /* Dark theme base */
    .stApp {
        background-color: #0d0d0d !important;
    }
    
    .main .block-container {
        padding: 2rem 2rem;
        max-width: 900px;
        margin: 0 auto;
    }
    
    /* Logo and branding */
    .logo-container {
        display: flex;
        flex-direction: column;
        align-items: center;
        justify-content: center;
        padding: 3rem 0 2rem 0;
    }
    
    .logo-icon {
        width: 64px;
        height: 64px;
        background: linear-gradient(135deg, #6366f1 0%, #8b5cf6 100%);
        border-radius: 16px;
        display: flex;
        align-items: center;
        justify-content: center;
        margin-bottom: 1rem;
    }
    
    .logo-icon svg {
        width: 36px;
        height: 36px;
        fill: white;
    }
    
    .logo-text {
        font-family: 'Inter', sans-serif;
        font-size: 2.5rem;
        font-weight: 700;
        color: #ffffff;
        letter-spacing: -0.5px;
    }
    
    /* Status indicators */
    .status-bar {
        display: flex;
        justify-content: center;
        gap: 2rem;
        padding: 0.75rem 1.5rem;
        background: rgba(255, 255, 255, 0.05);
        border-radius: 12px;
        margin: 1rem auto 2rem auto;
        max-width: 500px;
        border: 1px solid rgba(255, 255, 255, 0.1);
    }
    
    .status-item {
        display: flex;
        align-items: center;
        gap: 0.5rem;
        font-family: 'Inter', sans-serif;
        font-size: 0.85rem;
        color: #a1a1aa;
    }
    
    .status-dot {
        width: 8px;
        height: 8px;
        border-radius: 50%;
    }
    
    .status-online { background: #22c55e; box-shadow: 0 0 8px rgba(34, 197, 94, 0.5); }
    .status-offline { background: #ef4444; box-shadow: 0 0 8px rgba(239, 68, 68, 0.5); }
    
    /* Chat messages */
    .stChatMessage {
        background: transparent !important;
        border: none !important;
    }
    
    [data-testid="stChatMessageContent"] {
        background: rgba(255, 255, 255, 0.05) !important;
        border: 1px solid rgba(255, 255, 255, 0.1) !important;
        border-radius: 16px !important;
        color: #e4e4e7 !important;
        font-family: 'Inter', sans-serif !important;
    }
    
    [data-testid="stChatMessageContent"] p {
        color: #e4e4e7 !important;
    }
    
    /* User message styling */
    [data-testid="stChatMessage"][data-testid*="user"] [data-testid="stChatMessageContent"] {
        background: rgba(99, 102, 241, 0.15) !important;
        border: 1px solid rgba(99, 102, 241, 0.3) !important;
    }
    
    /* Chat input */
    .stChatInput {
        background: transparent !important;
    }
    
    .stChatInput > div {
        background: rgba(255, 255, 255, 0.05) !important;
        border: 1px solid rgba(255, 255, 255, 0.15) !important;
        border-radius: 28px !important;
    }
    
    .stChatInput textarea {
        background: transparent !important;
        color: #ffffff !important;
        font-family: 'Inter', sans-serif !important;
        caret-color: #6366f1 !important;
    }
    
    .stChatInput textarea::placeholder {
        color: #71717a !important;
    }
    
    .stChatInput button {
        background: linear-gradient(135deg, #6366f1 0%, #8b5cf6 100%) !important;
        border: none !important;
        border-radius: 50% !important;
    }
    
    /* Action buttons */
    .action-buttons {
        display: flex;
        justify-content: center;
        gap: 0.75rem;
        margin-top: 1rem;
        flex-wrap: wrap;
    }
    
    .action-btn {
        display: inline-flex;
        align-items: center;
        gap: 0.5rem;
        padding: 0.6rem 1.2rem;
        background: rgba(255, 255, 255, 0.05);
        border: 1px solid rgba(255, 255, 255, 0.15);
        border-radius: 24px;
        color: #a1a1aa;
        font-family: 'Inter', sans-serif;
        font-size: 0.875rem;
        font-weight: 500;
        cursor: pointer;
        transition: all 0.2s ease;
    }
    
    .action-btn:hover {
        background: rgba(255, 255, 255, 0.1);
        border-color: rgba(255, 255, 255, 0.25);
        color: #ffffff;
    }
    
    /* Security badge */
    .security-caption {
        font-family: 'Inter', sans-serif;
        font-size: 0.75rem;
        color: #71717a;
        margin-top: 0.5rem;
    }
    
    .security-caption.safe { color: #22c55e; }
    .security-caption.warn { color: #f59e0b; }
    .security-caption.block { color: #ef4444; }
    
    /* Streamlit button overrides */
    .stButton > button {
        background: rgba(255, 255, 255, 0.05) !important;
        border: 1px solid rgba(255, 255, 255, 0.15) !important;
        border-radius: 24px !important;
        color: #a1a1aa !important;
        font-family: 'Inter', sans-serif !important;
        font-weight: 500 !important;
        transition: all 0.2s ease !important;
    }
    
    .stButton > button:hover {
        background: rgba(255, 255, 255, 0.1) !important;
        border-color: rgba(255, 255, 255, 0.25) !important;
        color: #ffffff !important;
    }
    
    /* Stats display */
    .stats-container {
        display: flex;
        justify-content: center;
        gap: 1.5rem;
        margin-top: 0.5rem;
        font-family: 'Inter', sans-serif;
        font-size: 0.8rem;
        color: #52525b;
    }
    
    .stat-item {
        display: flex;
        align-items: center;
        gap: 0.35rem;
    }
    
    /* Divider */
    hr {
        border: none !important;
        border-top: 1px solid rgba(255, 255, 255, 0.1) !important;
        margin: 1rem 0 !important;
    }
    
    /* Caption styling */
    .stCaption {
        color: #71717a !important;
        font-family: 'Inter', sans-serif !important;
    }
    
    /* Hide default avatars and restyle */
    [data-testid="stChatMessageAvatarUser"],
    [data-testid="stChatMessageAvatarAssistant"] {
        background: linear-gradient(135deg, #6366f1 0%, #8b5cf6 100%) !important;
    }
    
    /* Markdown text in chat */
    .stMarkdown {
        color: #e4e4e7 !important;
    }
    
    /* Private indicator */
    .private-badge {
        position: fixed;
        top: 1rem;
        right: 1.5rem;
        display: flex;
        align-items: center;
        gap: 0.5rem;
        padding: 0.4rem 0.8rem;
        background: rgba(255, 255, 255, 0.05);
        border-radius: 20px;
        font-family: 'Inter', sans-serif;
        font-size: 0.8rem;
        color: #71717a;
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
    
    # Private badge (top right)
    st.markdown("""
    <div class="private-badge">
        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
            <rect x="3" y="11" width="18" height="11" rx="2" ry="2"></rect>
            <path d="M7 11V7a5 5 0 0 1 10 0v4"></path>
        </svg>
        Private
    </div>
    """, unsafe_allow_html=True)
    
    # Show welcome screen if no messages
    if not st.session_state.messages:
        # Centered logo
        st.markdown("""
        <div class="logo-container">
            <div class="logo-icon">
                <svg viewBox="0 0 24 24" fill="white">
                    <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
                </svg>
            </div>
            <span class="logo-text">Veil Armor</span>
        </div>
        """, unsafe_allow_html=True)
        
        # Status bar
        api_status = "online" if api_online else "offline"
        model_status = "online" if model else "offline"
        device_name = device.upper() if device else "N/A"
        
        st.markdown(f"""
        <div class="status-bar">
            <div class="status-item">
                <span class="status-dot status-{api_status}"></span>
                Security API
            </div>
            <div class="status-item">
                <span class="status-dot status-{model_status}"></span>
                Model ({device_name})
            </div>
        </div>
        """, unsafe_allow_html=True)
    
    # Check model
    if not model:
        st.error("Model not loaded. Please check configuration.")
        return
    
    # Chat history display
    for msg in st.session_state.messages:
        with st.chat_message(msg["role"]):
            st.markdown(msg["content"])
            if "security" in msg and msg["role"] == "assistant":
                sec = msg["security"]
                if sec.get("input_action") == "block":
                    st.caption("Input blocked")
                elif sec.get("input_action") == "redact":
                    st.caption(f"{sec.get('pii_count', 0)} items redacted")
                elif sec.get("output_redacted", 0) > 0:
                    st.caption("Output filtered")
                else:
                    st.caption("Verified secure")
    
    # Chat input
    if prompt := st.chat_input("What do you want to know?"):
        st.session_state.stats["total"] += 1
        
        # Security check input FIRST (before storing anything)
        security_info = {}
        should_block = False
        processed_prompt = prompt
        
        if security and api_online:
            should_continue, processed_prompt, input_sec = security.process_input(prompt)
            security_info["input_action"] = input_sec.get("action", "allow")
            security_info["pii_count"] = input_sec.get("pii_count", 0)
            
            if not should_continue:
                should_block = True
                st.session_state.stats["blocked"] += 1
                
                # Show blocked message (but DON'T store the original content)
                with st.chat_message("user"):
                    st.markdown("*[Message blocked - security threat detected]*")
                
                with st.chat_message("assistant"):
                    st.markdown("**Security Alert**: Your message was blocked due to detected security threats (prompt injection, jailbreak attempt, or PII). Please rephrase your request.")
                    st.caption("Input blocked")
                
                # Store sanitized placeholder instead of actual content
                st.session_state.messages.append({
                    "role": "user",
                    "content": "[Message blocked by security]"
                })
                st.session_state.messages.append({
                    "role": "assistant",
                    "content": "I cannot process that request due to security concerns. Please try a different question.",
                    "security": security_info
                })
                st.rerun()
                return
            
            if input_sec.get("action") == "redact":
                st.session_state.stats["sanitized"] += 1
        
        # Show user message (only if not blocked)
        with st.chat_message("user"):
            st.markdown(prompt)
        st.session_state.messages.append({"role": "user", "content": processed_prompt})
        
        # Generate response with streaming
        with st.chat_message("assistant"):
            # Build messages for model (use processed/sanitized content only)
            model_messages = [
                {"role": m["role"], "content": m["content"]}
                for m in st.session_state.messages[:-1]
            ]
            model_messages.append({"role": "user", "content": processed_prompt})
            
            # Stream response
            placeholder = st.empty()
            full_response = ""
            
            streamer = generate_stream(
                tokenizer, model, device, model_messages,
                max_tokens=512, temperature=0.7
            )
            
            if streamer:
                for chunk in streamer:
                    full_response += chunk
                    placeholder.markdown(full_response + "|")
                
                placeholder.markdown(full_response)
            else:
                full_response = "Sorry, I encountered an error generating a response."
                placeholder.markdown(full_response)
            
            # Security check output
            if security and api_online and full_response:
                safe_response, output_sec = security.process_output(full_response)
                security_info["output_redacted"] = output_sec.get("pii_redacted", 0)
                
                if safe_response != full_response:
                    placeholder.markdown(safe_response)
                    full_response = safe_response
            
            # Show security status
            if security_info.get("input_action") == "redact":
                st.caption(f"{security_info.get('pii_count', 0)} items redacted from input")
            elif security_info.get("output_redacted", 0) > 0:
                st.caption("Output filtered")
            else:
                st.caption("Verified secure")
                st.session_state.stats["clean"] += 1
        
        # Save to history
        st.session_state.messages.append({
            "role": "assistant",
            "content": full_response,
            "security": security_info
        })
    
    # Action buttons at the bottom (only show when no messages)
    if not st.session_state.messages:
        st.markdown("""
        <div class="action-buttons">
            <div class="action-btn">
                <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                    <circle cx="11" cy="11" r="8"></circle>
                    <path d="m21 21-4.35-4.35"></path>
                </svg>
                Secure Search
            </div>
            <div class="action-btn">
                <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                    <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
                </svg>
                Protected Mode
            </div>
            <div class="action-btn">
                <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                    <path d="M21 15a2 2 0 0 1-2 2H7l-4 4V5a2 2 0 0 1 2-2h14a2 2 0 0 1 2 2z"></path>
                </svg>
                Chat
            </div>
        </div>
        """, unsafe_allow_html=True)
        
        # Stats at the very bottom
        st.markdown(f"""
        <div class="stats-container">
            <div class="stat-item">Blocked: {st.session_state.stats['blocked']}</div>
            <div class="stat-item">Clean: {st.session_state.stats['clean']}</div>
            <div class="stat-item">Total: {st.session_state.stats['total']}</div>
        </div>
        """, unsafe_allow_html=True)
    
    # Clear button in sidebar area (subtle placement)
    if st.session_state.messages:
        col1, col2, col3 = st.columns([1, 1, 1])
        with col2:
            if st.button("Clear conversation", use_container_width=True):
                st.session_state.messages = []
                st.session_state.stats = {"total": 0, "blocked": 0, "sanitized": 0, "clean": 0}
                st.rerun()


if __name__ == "__main__":
    main()
