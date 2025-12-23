"""
Veil Armor - Unsecured Mode (Research Baseline)
Professional interface for comparison testing.
"""
import streamlit as st
import torch
from transformers import AutoTokenizer, AutoModelForCausalLM, TextIteratorStreamer
from threading import Thread
import os
from dotenv import load_dotenv

load_dotenv()

# ========================
# Configuration
# ========================
MODEL_NAME = "huihui-ai/Qwen2.5-3B-Instruct-abliterated"
HF_TOKEN = os.getenv("HF_TOKEN", "")

# ========================
# Page Setup
# ========================
st.set_page_config(
    page_title="Veil Armor - Baseline",
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
        --accent-primary: #f97316;
        --accent-secondary: #fb923c;
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
    
    .nav-mode {
        padding: 4px 10px;
        background: rgba(239, 68, 68, 0.15);
        border: 1px solid rgba(239, 68, 68, 0.3);
        border-radius: 6px;
        font-size: 11px;
        font-weight: 500;
        color: var(--error);
        text-transform: uppercase;
        letter-spacing: 0.5px;
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
    .status-dot.disabled { background: var(--text-muted); }
    
    .nav-actions {
        display: flex;
        align-items: center;
        gap: 12px;
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
        margin-bottom: 24px;
    }
    
    .warning-box {
        max-width: 500px;
        padding: 16px 20px;
        background: rgba(239, 68, 68, 0.1);
        border: 1px solid rgba(239, 68, 68, 0.2);
        border-radius: 10px;
        margin-bottom: 32px;
    }
    
    .warning-box-title {
        font-size: 13px;
        font-weight: 600;
        color: var(--error);
        margin-bottom: 4px;
    }
    
    .warning-box-text {
        font-size: 13px;
        color: var(--text-secondary);
        line-height: 1.5;
    }
    
    .feature-grid {
        display: grid;
        grid-template-columns: repeat(3, 1fr);
        gap: 12px;
        max-width: 500px;
        width: 100%;
    }
    
    .feature-card {
        padding: 16px;
        background: var(--bg-secondary);
        border: 1px solid var(--border-color);
        border-radius: 10px;
        text-align: center;
    }
    
    .feature-card.disabled {
        opacity: 0.5;
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
        background: #f97316 !important;
        border: none !important;
        border-radius: 50% !important;
    }
    
    .stChatInput button:hover,
    [data-testid="stChatInput"] button:hover {
        background: #fb923c !important;
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
    if "query_count" not in st.session_state:
        st.session_state.query_count = 0
    
    # Load model
    tokenizer, model, device = load_model()
    
    # Render navigation bar
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
            <span class="nav-mode">Baseline</span>
        </div>
        <div class="nav-status">
            <div class="status-indicator">
                <span class="status-dot disabled"></span>
                Security: Off
            </div>
            <div class="status-indicator">
                <span class="status-dot {model_status}"></span>
                Model ({device_name})
            </div>
        </div>
        <div class="nav-actions">
            <span style="font-size: 12px; color: var(--text-muted);">
                Session: {st.session_state.query_count} queries
            </span>
        </div>
    </div>
    <div class="content-wrapper">
    """, unsafe_allow_html=True)
    
    # Check model
    if not model:
        st.error("Model initialization failed. Check configuration and restart.")
        return
    
    # Welcome state
    if not st.session_state.messages:
        st.markdown("""
        <div class="welcome-container">
            <div class="welcome-icon">
                <svg viewBox="0 0 24 24" fill="white">
                    <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
                </svg>
            </div>
            <div class="welcome-title">Veil Armor</div>
            <div class="welcome-subtitle">Baseline Mode - No Security Filters</div>
            <div class="warning-box">
                <div class="warning-box-title">Research Mode Active</div>
                <div class="warning-box-text">
                    Security protections are disabled. This interface serves as a baseline 
                    for comparing model behavior with and without Veil Armor protection.
                </div>
            </div>
            <div class="feature-grid">
                <div class="feature-card disabled">
                    <div class="feature-card-title">Input Scanning</div>
                    <div class="feature-card-desc">Disabled</div>
                </div>
                <div class="feature-card disabled">
                    <div class="feature-card-title">PII Protection</div>
                    <div class="feature-card-desc">Disabled</div>
                </div>
                <div class="feature-card disabled">
                    <div class="feature-card-title">Output Filtering</div>
                    <div class="feature-card-desc">Disabled</div>
                </div>
            </div>
        </div>
        """, unsafe_allow_html=True)
    
    # Chat history
    for msg in st.session_state.messages:
        with st.chat_message(msg["role"]):
            st.markdown(msg["content"])
    
    st.markdown("</div>", unsafe_allow_html=True)
    
    # Chat input
    if prompt := st.chat_input("Enter your query..."):
        st.session_state.query_count += 1
        
        with st.chat_message("user"):
            st.markdown(prompt)
        st.session_state.messages.append({"role": "user", "content": prompt})
        
        with st.chat_message("assistant"):
            model_messages = [
                {"role": m["role"], "content": m["content"]}
                for m in st.session_state.messages
            ]
            
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
        
        st.session_state.messages.append({
            "role": "assistant",
            "content": full_response
        })
    
    # Clear button
    if st.session_state.messages:
        col1, col2, col3 = st.columns([2, 1, 2])
        with col2:
            if st.button("Clear Session", use_container_width=True):
                st.session_state.messages = []
                st.session_state.query_count = 0
                st.rerun()


if __name__ == "__main__":
    main()
