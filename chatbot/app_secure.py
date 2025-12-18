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
    page_title="Veil Armor Chat",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="collapsed"
)

# Professional CSS
st.markdown("""
<style>
    /* Hide Streamlit branding */
    #MainMenu {visibility: hidden;}
    footer {visibility: hidden;}
    header {visibility: hidden;}
    
    /* Main container */
    .main .block-container {
        padding: 1rem 2rem;
        max-width: 1200px;
    }
    
    /* Header */
    .header-container {
        display: flex;
        align-items: center;
        justify-content: space-between;
        padding: 0.5rem 0;
        border-bottom: 1px solid #e0e0e0;
        margin-bottom: 1rem;
    }
    .header-title {
        font-size: 1.5rem;
        font-weight: 600;
        color: #1a1a2e;
        display: flex;
        align-items: center;
        gap: 0.5rem;
    }
    .header-badge {
        font-size: 0.7rem;
        background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
        color: white;
        padding: 3px 10px;
        border-radius: 12px;
    }
    
    /* Status bar */
    .status-bar {
        display: flex;
        gap: 1.5rem;
        padding: 0.5rem 1rem;
        background: #f8f9fa;
        border-radius: 8px;
        margin-bottom: 1rem;
        font-size: 0.85rem;
    }
    .status-item {
        display: flex;
        align-items: center;
        gap: 0.4rem;
    }
    .status-dot {
        width: 8px;
        height: 8px;
        border-radius: 50%;
    }
    .status-online { background: #22c55e; }
    .status-offline { background: #ef4444; }
    
    /* Chat container */
    .chat-container {
        height: calc(100vh - 280px);
        overflow-y: auto;
        padding: 1rem;
        background: #ffffff;
        border-radius: 12px;
        border: 1px solid #e5e7eb;
    }
    
    /* Messages */
    .message {
        display: flex;
        gap: 0.75rem;
        margin-bottom: 1rem;
        animation: fadeIn 0.3s ease;
    }
    @keyframes fadeIn {
        from { opacity: 0; transform: translateY(10px); }
        to { opacity: 1; transform: translateY(0); }
    }
    .message-avatar {
        width: 32px;
        height: 32px;
        border-radius: 50%;
        display: flex;
        align-items: center;
        justify-content: center;
        font-size: 0.9rem;
        flex-shrink: 0;
    }
    .user-avatar { background: #e0e7ff; }
    .assistant-avatar { background: #d1fae5; }
    .message-content {
        flex: 1;
        padding: 0.75rem 1rem;
        border-radius: 12px;
        line-height: 1.5;
    }
    .user-message { background: #f3f4f6; }
    .assistant-message { background: #f0fdf4; border: 1px solid #bbf7d0; }
    
    /* Security badge in message */
    .security-badge {
        display: inline-flex;
        align-items: center;
        gap: 4px;
        font-size: 0.7rem;
        padding: 2px 8px;
        border-radius: 10px;
        margin-top: 0.5rem;
    }
    .badge-safe { background: #dcfce7; color: #166534; }
    .badge-warn { background: #fef3c7; color: #92400e; }
    .badge-block { background: #fee2e2; color: #991b1b; }
    
    /* Input area */
    .stChatInput {
        border-radius: 24px !important;
    }
    .stChatInput > div {
        border-radius: 24px !important;
    }
    
    /* Sidebar */
    .sidebar-header {
        font-size: 1.1rem;
        font-weight: 600;
        margin-bottom: 1rem;
        padding-bottom: 0.5rem;
        border-bottom: 1px solid #e5e7eb;
    }
    .stat-card {
        background: #f8fafc;
        padding: 0.75rem;
        border-radius: 8px;
        margin-bottom: 0.5rem;
    }
    .stat-label {
        font-size: 0.75rem;
        color: #64748b;
    }
    .stat-value {
        font-size: 1.25rem;
        font-weight: 600;
        color: #1e293b;
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
    
    # Header
    st.markdown("""
    <div class="header-container">
        <div class="header-title">
            🛡️ Veil Armor Chat
            <span class="header-badge">SECURED</span>
        </div>
    </div>
    """, unsafe_allow_html=True)
    
    # Status bar
    api_status = "online" if api_online else "offline"
    model_status = "online" if model else "offline"
    
    col1, col2, col3, col4 = st.columns([2, 2, 2, 1])
    with col1:
        st.markdown(f"""
        <div class="status-item">
            <span class="status-dot status-{api_status}"></span>
            Security API: {api_status.title()}
        </div>
        """, unsafe_allow_html=True)
    with col2:
        st.markdown(f"""
        <div class="status-item">
            <span class="status-dot status-{model_status}"></span>
            Model: {device.upper() if device else 'N/A'}
        </div>
        """, unsafe_allow_html=True)
    with col3:
        st.markdown(f"""
        <div class="status-item">
            🛡️ Blocked: {st.session_state.stats['blocked']} | 
            ✅ Clean: {st.session_state.stats['clean']}
        </div>
        """, unsafe_allow_html=True)
    with col4:
        if st.button("🗑️ Clear", use_container_width=True):
            st.session_state.messages = []
            st.session_state.stats = {"total": 0, "blocked": 0, "sanitized": 0, "clean": 0}
            st.rerun()
    
    st.markdown("<hr style='margin: 0.5rem 0; border: none; border-top: 1px solid #e5e7eb;'>", unsafe_allow_html=True)
    
    # Check model
    if not model:
        st.error("⚠️ Model not loaded. Please check configuration.")
        return
    
    # Chat history
    for msg in st.session_state.messages:
        with st.chat_message(msg["role"]):
            st.markdown(msg["content"])
            if "security" in msg and msg["role"] == "assistant":
                sec = msg["security"]
                if sec.get("input_action") == "block":
                    st.caption("🔴 Input blocked")
                elif sec.get("input_action") == "redact":
                    st.caption(f"🟡 {sec.get('pii_count', 0)} PII redacted")
                elif sec.get("output_redacted", 0) > 0:
                    st.caption(f"🟡 Output filtered")
                else:
                    st.caption("🟢 Secure")
    
    # Chat input
    if prompt := st.chat_input("Type your message..."):
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
                    st.markdown("🚫 *[Message blocked - security threat detected]*")
                
                with st.chat_message("assistant"):
                    st.markdown("⚠️ **Security Alert**: Your message was blocked due to detected security threats (prompt injection, jailbreak attempt, or PII). Please rephrase your request.")
                    st.caption("🔴 Input blocked")
                
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
                    placeholder.markdown(full_response + "▌")
                
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
                st.caption(f"🟡 {security_info.get('pii_count', 0)} PII redacted from input")
            elif security_info.get("output_redacted", 0) > 0:
                st.caption(f"🟡 Output filtered")
            else:
                st.caption("🟢 Secure")
                st.session_state.stats["clean"] += 1
        
        # Save to history
        st.session_state.messages.append({
            "role": "assistant",
            "content": full_response,
            "security": security_info
        })


if __name__ == "__main__":
    main()
