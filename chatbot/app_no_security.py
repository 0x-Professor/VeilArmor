"""
Basic Chatbot with Qwen3-8B Abliterated Model (NO SECURITY)
This version tests the raw model without Modal Armor protection.

WARNING: This is an uncensored model - use with caution!
"""
import streamlit as st
import torch
from transformers import AutoTokenizer, AutoModelForCausalLM
import time
import os
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# ========================
# Page Configuration
# ========================
st.set_page_config(
    page_title="Qwen3 Abliterated Chat (No Security)",
    page_icon="⚠️",
    layout="wide"
)

# Custom CSS
st.markdown("""
<style>
    .warning-header {
        background-color: #ff5722;
        color: white;
        padding: 10px 20px;
        border-radius: 5px;
        text-align: center;
        margin-bottom: 20px;
    }
</style>
""", unsafe_allow_html=True)

# ========================
# Constants
# ========================
# Using smaller 3B model for faster responses (same author, abliterated)
MODEL_NAME = "huihui-ai/Qwen2.5-3B-Instruct-abliterated"
HF_TOKEN = os.getenv("HF_TOKEN", "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")


# ========================
# Model Loading (Cached)
# ========================
@st.cache_resource
def load_model():
    """Load and cache the Qwen3 model and tokenizer."""
    try:
        st.info(f"Loading model: {MODEL_NAME}")
        
        tokenizer = AutoTokenizer.from_pretrained(
            MODEL_NAME,
            trust_remote_code=True,
            token=HF_TOKEN if HF_TOKEN else None
        )
        
        # Check for GPU availability
        device = "cuda" if torch.cuda.is_available() else "cpu"
        st.info(f"Using device: {device}")
        
        # Load model with appropriate settings
        if device == "cuda":
            model = AutoModelForCausalLM.from_pretrained(
                MODEL_NAME,
                torch_dtype=torch.float16,
                device_map="auto",
                trust_remote_code=True,
                token=HF_TOKEN if HF_TOKEN else None
            )
        else:
            # CPU mode - use float32
            model = AutoModelForCausalLM.from_pretrained(
                MODEL_NAME,
                torch_dtype=torch.float32,
                low_cpu_mem_usage=True,
                trust_remote_code=True,
                token=HF_TOKEN if HF_TOKEN else None
            )
        
        return tokenizer, model, device
            
    except Exception as e:
        st.error(f"Failed to load model: {str(e)}")
        import traceback
        st.code(traceback.format_exc())
        return None, None, None


def generate_response(tokenizer, model, device, messages, max_new_tokens=256, temperature=0.7):
    """Generate response from Qwen3 model."""
    try:
        # Apply chat template
        inputs = tokenizer.apply_chat_template(
            messages,
            add_generation_prompt=True,
            tokenize=True,
            return_dict=True,
            return_tensors="pt"
        )
        
        # Move to device
        if device == "cuda":
            inputs = {k: v.to(device) for k, v in inputs.items()}
        
        # Generate
        with torch.no_grad():
            outputs = model.generate(
                **inputs,
                max_new_tokens=max_new_tokens,
                temperature=temperature,
                do_sample=True if temperature > 0 else False,
                top_p=0.9,
                pad_token_id=tokenizer.eos_token_id
            )
        
        # Decode response (only new tokens)
        input_length = inputs["input_ids"].shape[1]
        generated_tokens = outputs[0][input_length:]
        response = tokenizer.decode(generated_tokens, skip_special_tokens=True)
        
        return response.strip()
        
    except Exception as e:
        return f"Error generating response: {str(e)}"


# ========================
# Main Application
# ========================
def main():
    # Warning header
    st.markdown("""
    <div class="warning-header">
        ⚠️ ABLITERATED MODEL - NO SECURITY ENABLED ⚠️<br>
        <small>This is an uncensored model for testing purposes only</small>
    </div>
    """, unsafe_allow_html=True)
    
    st.title("🤖 Qwen3-8B Abliterated Chatbot")
    st.caption("Testing raw model without Modal Armor protection")
    
    # Sidebar
    with st.sidebar:
        st.header("⚙️ Settings")
        max_tokens = st.slider("Max Tokens", 64, 1024, 256, step=64)
        temperature = st.slider("Temperature", 0.0, 2.0, 0.7, step=0.1)
        
        st.divider()
        
        st.warning("""
        **⚠️ No Security Active**
        
        This chatbot has NO:
        - Prompt injection protection
        - PII detection/redaction
        - Content filtering
        
        All inputs go directly to the model.
        """)
        
        if st.button("🗑️ Clear Chat", use_container_width=True):
            st.session_state.messages = []
            st.rerun()
    
    # Initialize session state
    if "messages" not in st.session_state:
        st.session_state.messages = []
    
    # Load model
    with st.spinner("Loading Qwen3-8B model... (this may take a few minutes on first run)"):
        tokenizer, model, device = load_model()
    
    if tokenizer is None or model is None:
        st.error("❌ Model failed to load. Check the error above.")
        return
    
    st.success(f"✅ Model loaded on {device.upper()}")
    
    # Display chat history
    for message in st.session_state.messages:
        with st.chat_message(message["role"]):
            st.markdown(message["content"])
    
    # Chat input
    if prompt := st.chat_input("Type your message (no security filtering)..."):
        # Display user message
        with st.chat_message("user"):
            st.markdown(prompt)
        
        # Add to history
        st.session_state.messages.append({"role": "user", "content": prompt})
        
        # Generate response
        with st.chat_message("assistant"):
            with st.spinner("Thinking..."):
                start_time = time.time()
                
                # Prepare messages for model
                model_messages = [
                    {"role": m["role"], "content": m["content"]}
                    for m in st.session_state.messages
                ]
                
                response = generate_response(
                    tokenizer=tokenizer,
                    model=model,
                    device=device,
                    messages=model_messages,
                    max_new_tokens=max_tokens,
                    temperature=temperature
                )
                
                gen_time = time.time() - start_time
            
            st.markdown(response)
            st.caption(f"⏱️ Generated in {gen_time:.1f}s | ⚠️ No security filtering applied")
        
        # Save to history
        st.session_state.messages.append({"role": "assistant", "content": response})


if __name__ == "__main__":
    main()
