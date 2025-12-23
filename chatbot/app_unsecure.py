"""
Abliterated Chatbot - No Security (For Testing)
Clean, minimal UI with streaming.
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
    page_title="Veil Armor - Unsecured",
    page_icon="VA",
    layout="wide",
    initial_sidebar_state="collapsed"
)

# Professional Dark Theme CSS (Matching Secure Version)
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
        background: linear-gradient(135deg, #ef4444 0%, #f97316 100%);
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
    
    .logo-subtitle {
        font-family: 'Inter', sans-serif;
        font-size: 0.9rem;
        color: #f97316;
        margin-top: 0.25rem;
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
    
    /* Warning banner */
    .warning-banner {
        display: flex;
        align-items: center;
        justify-content: center;
        gap: 0.5rem;
        padding: 0.75rem 1.5rem;
        background: rgba(239, 68, 68, 0.15);
        border: 1px solid rgba(239, 68, 68, 0.3);
        border-radius: 12px;
        margin: 0 auto 1.5rem auto;
        max-width: 600px;
        font-family: 'Inter', sans-serif;
        font-size: 0.85rem;
        color: #fca5a5;
    }
    
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
        background: rgba(249, 115, 22, 0.15) !important;
        border: 1px solid rgba(249, 115, 22, 0.3) !important;
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
        caret-color: #f97316 !important;
    }
    
    .stChatInput textarea::placeholder {
        color: #71717a !important;
    }
    
    .stChatInput button {
        background: linear-gradient(135deg, #ef4444 0%, #f97316 100%) !important;
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
        background: linear-gradient(135deg, #ef4444 0%, #f97316 100%) !important;
    }
    
    /* Markdown text in chat */
    .stMarkdown {
        color: #e4e4e7 !important;
    }
    
    /* Unsecured indicator */
    .unsecured-badge {
        position: fixed;
        top: 1rem;
        right: 1.5rem;
        display: flex;
        align-items: center;
        gap: 0.5rem;
        padding: 0.4rem 0.8rem;
        background: rgba(239, 68, 68, 0.15);
        border: 1px solid rgba(239, 68, 68, 0.3);
        border-radius: 20px;
        font-family: 'Inter', sans-serif;
        font-size: 0.8rem;
        color: #fca5a5;
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
    
    # Load model
    tokenizer, model, device = load_model()
    
    # Unsecured badge (top right)
    st.markdown("""
    <div class="unsecured-badge">
        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
            <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
            <line x1="4" y1="4" x2="20" y2="20" stroke="#fca5a5" stroke-width="2"/>
        </svg>
        Unsecured
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
            <span class="logo-subtitle">Unsecured Mode</span>
        </div>
        """, unsafe_allow_html=True)
        
        # Warning banner
        st.markdown("""
        <div class="warning-banner">
            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                <path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"></path>
                <line x1="12" y1="9" x2="12" y2="13"></line>
                <line x1="12" y1="17" x2="12.01" y2="17"></line>
            </svg>
            This is an uncensored model with no security protection. For testing only.
        </div>
        """, unsafe_allow_html=True)
        
        # Status bar
        model_status = "online" if model else "offline"
        device_name = device.upper() if device else "N/A"
        
        st.markdown(f"""
        <div class="status-bar">
            <div class="status-item">
                <span class="status-dot status-offline"></span>
                Security: Disabled
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
    
    # Chat history
    for msg in st.session_state.messages:
        with st.chat_message(msg["role"]):
            st.markdown(msg["content"])
    
    # Chat input
    if prompt := st.chat_input("What do you want to know?"):
        # Show user message
        with st.chat_message("user"):
            st.markdown(prompt)
        st.session_state.messages.append({"role": "user", "content": prompt})
        
        # Generate with streaming
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
                    placeholder.markdown(full_response + "|")
                placeholder.markdown(full_response)
            else:
                full_response = "Error generating response."
                placeholder.markdown(full_response)
        
        st.session_state.messages.append({
            "role": "assistant",
            "content": full_response
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
                Search
            </div>
            <div class="action-btn">
                <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                    <path d="M21 15a2 2 0 0 1-2 2H7l-4 4V5a2 2 0 0 1 2-2h14a2 2 0 0 1 2 2z"></path>
                </svg>
                Chat
            </div>
            <div class="action-btn">
                <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                    <polygon points="13 2 3 14 12 14 11 22 21 10 12 10 13 2"></polygon>
                </svg>
                Generate
            </div>
        </div>
        """, unsafe_allow_html=True)
    
    # Clear button (only show when there are messages)
    if st.session_state.messages:
        col1, col2, col3 = st.columns([1, 1, 1])
        with col2:
            if st.button("Clear conversation", use_container_width=True):
                st.session_state.messages = []
                st.rerun()


if __name__ == "__main__":
    main()
