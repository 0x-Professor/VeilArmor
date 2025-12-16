"""
Modal Armor Secure Chatbot
A Streamlit chatbot using abliterated Qwen3-8B model protected by Modal Armor security.

Security Flow:
1. User enters prompt
2. Modal Armor checks for prompt injection & PII
3. If safe/sanitized, send to Qwen3 model
4. Check model output for sensitive data
5. Redact/remove sensitive info
6. Display safe response

Author: Modal Armor Team
"""
import streamlit as st
import torch
from transformers import AutoTokenizer, AutoModelForCausalLM
import time
import os
from dotenv import load_dotenv

# Import security client
from security_client import SecurityPipeline

# Load environment variables
load_dotenv()

# ========================
# Page Configuration
# ========================
st.set_page_config(
    page_title="Modal Armor Secure Chat",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom CSS for better UI
st.markdown("""
<style>
    .main-header {
        font-size: 2.5rem;
        font-weight: bold;
        color: #1E88E5;
        text-align: center;
        margin-bottom: 0.5rem;
    }
    .sub-header {
        font-size: 1rem;
        color: #666;
        text-align: center;
        margin-bottom: 2rem;
    }
    .security-badge {
        background-color: #4CAF50;
        color: white;
        padding: 4px 12px;
        border-radius: 15px;
        font-size: 0.8rem;
    }
    .warning-badge {
        background-color: #FF9800;
        color: white;
        padding: 4px 12px;
        border-radius: 15px;
        font-size: 0.8rem;
    }
    .blocked-badge {
        background-color: #f44336;
        color: white;
        padding: 4px 12px;
        border-radius: 15px;
        font-size: 0.8rem;
    }
    .stChatMessage {
        background-color: #f8f9fa;
        border-radius: 10px;
        margin: 5px 0;
    }
</style>
""", unsafe_allow_html=True)


# ========================
# Constants
# ========================
MODEL_NAME = "huihui-ai/Huihui-Qwen3-8B-abliterated-v2"
MODAL_ARMOR_API_URL = os.getenv("MODAL_ARMOR_API_URL", "http://localhost:8000")
HF_TOKEN = os.getenv("HF_TOKEN", "")


# ========================
# Model Loading (Cached)
# ========================
@st.cache_resource
def load_model():
    """Load and cache the Qwen3 model and tokenizer."""
    try:
        with st.spinner("Loading Qwen3-8B model... This may take a few minutes."):
            tokenizer = AutoTokenizer.from_pretrained(
                MODEL_NAME,
                trust_remote_code=True,
                token=HF_TOKEN if HF_TOKEN else None
            )
            
            # Check for GPU availability
            device = "cuda" if torch.cuda.is_available() else "cpu"
            
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
                model = AutoModelForCausalLM.from_pretrained(
                    MODEL_NAME,
                    torch_dtype=torch.float32,
                    trust_remote_code=True,
                    token=HF_TOKEN if HF_TOKEN else None
                )
                model = model.to(device)
            
            return tokenizer, model, device
            
    except Exception as e:
        st.error(f"Failed to load model: {str(e)}")
        return None, None, None


@st.cache_resource
def load_security_pipeline():
    """Initialize security pipeline."""
    return SecurityPipeline(api_url=MODAL_ARMOR_API_URL)


# ========================
# Generation Function
# ========================
def generate_response(
    tokenizer,
    model,
    device: str,
    messages: list,
    max_new_tokens: int = 512,
    temperature: float = 0.7,
    do_sample: bool = True
) -> str:
    """
    Generate response from Qwen3 model.
    
    Args:
        tokenizer: Model tokenizer
        model: The Qwen3 model
        device: Device to use (cuda/cpu)
        messages: Chat history in OpenAI format
        max_new_tokens: Maximum tokens to generate
        temperature: Sampling temperature
        do_sample: Whether to use sampling
        
    Returns:
        Generated response text
    """
    try:
        # Apply chat template
        inputs = tokenizer.apply_chat_template(
            messages,
            add_generation_prompt=True,
            tokenize=True,
            return_dict=True,
            return_tensors="pt"
        ).to(device)
        
        # Generate
        with torch.no_grad():
            outputs = model.generate(
                **inputs,
                max_new_tokens=max_new_tokens,
                temperature=temperature,
                do_sample=do_sample,
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
    # Header
    st.markdown('<p class="main-header">🛡️ Modal Armor Secure Chat</p>', unsafe_allow_html=True)
    st.markdown('<p class="sub-header">Powered by Qwen3-8B (Abliterated) | Protected by Modal Armor Security</p>', unsafe_allow_html=True)
    
    # Sidebar
    with st.sidebar:
        st.header("⚙️ Settings")
        
        # Generation parameters
        st.subheader("Model Settings")
        max_tokens = st.slider("Max Tokens", 64, 2048, 512, step=64)
        temperature = st.slider("Temperature", 0.1, 2.0, 0.7, step=0.1)
        
        st.divider()
        
        # Security status
        st.subheader("🔒 Security Status")
        security_pipeline = load_security_pipeline()
        
        if security_pipeline.is_api_available():
            st.success("Modal Armor API: Online")
        else:
            st.warning("Modal Armor API: Offline (Fail-safe mode)")
        
        # Security stats
        if "security_stats" in st.session_state:
            stats = st.session_state.security_stats
            col1, col2 = st.columns(2)
            with col1:
                st.metric("Inputs Checked", stats.get("inputs_checked", 0))
                st.metric("Blocked", stats.get("inputs_blocked", 0))
            with col2:
                st.metric("Redacted", stats.get("inputs_redacted", 0))
                st.metric("Output Filtered", stats.get("outputs_redacted", 0))
        
        st.divider()
        
        # Model info
        st.subheader("📊 Model Info")
        st.info(f"""
        **Model:** Qwen3-8B  
        **Variant:** Abliterated (Uncensored)  
        **Security:** Modal Armor Protected
        """)
        
        # Clear chat button
        if st.button("🗑️ Clear Chat History", use_container_width=True):
            st.session_state.messages = []
            st.session_state.security_stats = {
                "inputs_checked": 0,
                "inputs_blocked": 0,
                "inputs_redacted": 0,
                "outputs_redacted": 0
            }
            st.rerun()
    
    # Initialize session state
    if "messages" not in st.session_state:
        st.session_state.messages = []
    
    if "security_stats" not in st.session_state:
        st.session_state.security_stats = {
            "inputs_checked": 0,
            "inputs_blocked": 0,
            "inputs_redacted": 0,
            "outputs_redacted": 0
        }
    
    # Load model
    tokenizer, model, device = load_model()
    
    if tokenizer is None or model is None:
        st.error("⚠️ Model failed to load. Please check your configuration and try again.")
        st.info("""
        **Troubleshooting:**
        1. Ensure you have enough GPU memory (16GB+ recommended)
        2. Set HF_TOKEN environment variable if needed
        3. Check your internet connection for model download
        """)
        return
    
    st.success(f"✅ Model loaded on {device.upper()}")
    
    # Display chat history
    for i, message in enumerate(st.session_state.messages):
        with st.chat_message(message["role"]):
            st.markdown(message["content"])
            
            # Show security info for assistant messages
            if message["role"] == "assistant" and "security_info" in message:
                sec_info = message["security_info"]
                
                # Input security
                if "input" in sec_info:
                    input_action = sec_info["input"].get("action", "unknown")
                    if input_action == "allow":
                        st.caption("🟢 Input: Clean")
                    elif input_action == "redact":
                        st.caption(f"🟡 Input: {sec_info['input'].get('pii_count', 0)} PII redacted")
                    elif input_action == "block":
                        st.caption("🔴 Input: Blocked")
                
                # Output security
                if "output" in sec_info:
                    if sec_info["output"].get("pii_redacted", 0) > 0:
                        st.caption(f"🟡 Output: {sec_info['output']['pii_redacted']} PII redacted")
    
    # Chat input
    if prompt := st.chat_input("Type your message here..."):
        # Display user message immediately
        with st.chat_message("user"):
            st.markdown(prompt)
        
        # Add to history (original prompt for display)
        st.session_state.messages.append({"role": "user", "content": prompt})
        
        # Process through security pipeline
        security_pipeline = load_security_pipeline()
        
        # 1. Check input security
        should_continue, processed_prompt, input_security = security_pipeline.process_input(
            prompt=prompt,
            user_id="streamlit_user"
        )
        
        # Update stats
        st.session_state.security_stats["inputs_checked"] += 1
        
        if not should_continue:
            # Input blocked
            st.session_state.security_stats["inputs_blocked"] += 1
            
            with st.chat_message("assistant"):
                blocked_msg = "⚠️ **Security Alert**: Your message was blocked due to potential security threats detected (e.g., prompt injection attempt). Please rephrase your question."
                st.markdown(blocked_msg)
                st.caption(f"🔴 Threats detected: {', '.join(input_security.get('threats', []))}")
            
            st.session_state.messages.append({
                "role": "assistant",
                "content": blocked_msg,
                "security_info": {"input": input_security}
            })
        else:
            # Check if input was redacted
            if input_security.get("action") == "redact":
                st.session_state.security_stats["inputs_redacted"] += 1
            
            # 2. Generate response using sanitized prompt
            with st.chat_message("assistant"):
                with st.spinner("Thinking..."):
                    # Prepare messages for model (use processed/sanitized prompt)
                    model_messages = []
                    for msg in st.session_state.messages[:-1]:  # Exclude last user message
                        model_messages.append({
                            "role": msg["role"],
                            "content": msg["content"]
                        })
                    
                    # Add sanitized current prompt
                    model_messages.append({
                        "role": "user",
                        "content": processed_prompt
                    })
                    
                    # Generate
                    start_time = time.time()
                    raw_response = generate_response(
                        tokenizer=tokenizer,
                        model=model,
                        device=device,
                        messages=model_messages,
                        max_new_tokens=max_tokens,
                        temperature=temperature
                    )
                    gen_time = time.time() - start_time
                
                # 3. Check output security
                safe_response, output_security = security_pipeline.process_output(
                    response=raw_response,
                    user_id="streamlit_user"
                )
                
                if output_security.get("pii_redacted", 0) > 0:
                    st.session_state.security_stats["outputs_redacted"] += 1
                
                # Display response
                st.markdown(safe_response)
                
                # Show security status
                col1, col2, col3 = st.columns(3)
                with col1:
                    if input_security.get("action") == "allow":
                        st.caption("🟢 Input: Clean")
                    elif input_security.get("action") == "redact":
                        st.caption(f"🟡 Input: {input_security.get('pii_count', 0)} PII redacted")
                
                with col2:
                    if output_security.get("pii_redacted", 0) > 0:
                        st.caption(f"🟡 Output: {output_security['pii_redacted']} PII redacted")
                    else:
                        st.caption("🟢 Output: Clean")
                
                with col3:
                    st.caption(f"⏱️ {gen_time:.1f}s")
            
            # Save to history
            st.session_state.messages.append({
                "role": "assistant",
                "content": safe_response,
                "security_info": {
                    "input": input_security,
                    "output": output_security
                }
            })


if __name__ == "__main__":
    main()
