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
    page_title="Abliterated Chat (Unsecured)",
    page_icon="⚠️",
    layout="wide",
    initial_sidebar_state="collapsed"
)

# Clean CSS
st.markdown("""
<style>
    #MainMenu {visibility: hidden;}
    footer {visibility: hidden;}
    header {visibility: hidden;}
    
    .main .block-container {
        padding: 1rem 2rem;
        max-width: 1000px;
    }
    
    .warning-banner {
        background: linear-gradient(135deg, #ff6b6b 0%, #ee5a24 100%);
        color: white;
        padding: 0.75rem 1rem;
        border-radius: 8px;
        margin-bottom: 1rem;
        text-align: center;
        font-weight: 500;
    }
    
    .header-title {
        font-size: 1.5rem;
        font-weight: 600;
        color: #1a1a2e;
        text-align: center;
        margin-bottom: 0.5rem;
    }
    
    .status-bar {
        display: flex;
        justify-content: center;
        gap: 2rem;
        padding: 0.5rem;
        background: #f8f9fa;
        border-radius: 8px;
        margin-bottom: 1rem;
        font-size: 0.85rem;
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
    
    # Header
    st.markdown('<p class="header-title">⚠️ Abliterated Chat (No Security)</p>', unsafe_allow_html=True)
    st.markdown("""
    <div class="warning-banner">
        🚨 WARNING: This is an UNCENSORED model with NO security protection. For testing only!
    </div>
    """, unsafe_allow_html=True)
    
    # Status
    col1, col2, col3 = st.columns([3, 3, 1])
    with col1:
        st.caption(f"Model: {MODEL_NAME.split('/')[-1]}")
    with col2:
        st.caption(f"Device: {device.upper() if device else 'N/A'}")
    with col3:
        if st.button("Clear"):
            st.session_state.messages = []
            st.rerun()
    
    st.divider()
    
    # Check model
    if not model:
        st.error("Model not loaded")
        return
    
    # Chat history
    for msg in st.session_state.messages:
        with st.chat_message(msg["role"]):
            st.markdown(msg["content"])
    
    # Chat input
    if prompt := st.chat_input("Type your message..."):
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
                    placeholder.markdown(full_response + "▌")
                placeholder.markdown(full_response)
            else:
                full_response = "Error generating response."
                placeholder.markdown(full_response)
        
        st.session_state.messages.append({
            "role": "assistant",
            "content": full_response
        })


if __name__ == "__main__":
    main()
