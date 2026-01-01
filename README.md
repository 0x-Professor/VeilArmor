# 🛡️ Veil Armor - LLM Security Framework

**Veil Armor** is an enterprise-grade security framework for Large Language Models (LLMs) that provides multi-layered protection against prompt injections, jailbreaks, PII leakage, and sophisticated attack vectors.

## 🎯 Key Features

- **100% Attack Detection Rate** - Tested against 42 zero-day attack vectors
- **Prompt Injection Detection** - Real-time detection using Vigil TransformerScanner
- **Jailbreak Prevention** - 30+ custom regex patterns for bypasses Vigil misses
- **PII Protection** - Microsoft Presidio integration for sensitive data detection
- **Real-time Security API** - FastAPI-powered RESTful endpoints
- **Kubernetes Ready** - Health checks, metrics, and deployment manifests included
- **Docker Support** - Multi-stage production builds

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                     Veil Armor API                          │
├─────────────────────────────────────────────────────────────┤
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐      │
│  │   Vigil      │  │  Presidio    │  │   Custom     │      │
│  │  Scanner     │  │  PII Engine  │  │  Patterns    │      │
│  └──────────────┘  └──────────────┘  └──────────────┘      │
├─────────────────────────────────────────────────────────────┤
│                    FastAPI Server                           │
└─────────────────────────────────────────────────────────────┘
```

## 📋 Requirements

- Python 3.10+
- CUDA (optional, for GPU acceleration)
- Docker (optional, for containerized deployment)

## 🚀 Quick Start

### 1. Clone and Setup

```bash
git clone https://github.com/0x-Professor/VeilArmor.git
cd veil-armor
python -m venv venv
venv\Scripts\activate  # Windows
source venv/bin/activate  # Linux/Mac
pip install -r requirements.txt
python -m spacy download en_core_web_lg
```

### 2. Configure Environment

Create a `.env` file:

```env
VEIL_ARMOR_API_KEY=your_secret_api_key_here
GEMINI_API_KEY=your_gemini_key_here  # Optional
HF_TOKEN=your_huggingface_token_here  # For chatbot models
```

### 3. Start the Security API

```bash
cd src/veil_armor/api
python server.py
```

The API will be available at `http://localhost:8000`

## 🔐 API Usage

### Health Check

```bash
curl http://localhost:8000/health
```

### Security Check

```bash
curl -X POST http://localhost:8000/api/v1/check \
  -H "Content-Type: application/json" \
  -H "X-API-Key: your_api_key" \
  -d '{
    "prompt": "Your user input here",
    "user_id": "user123",
    "check_pii": true,
    "check_injection": true
  }'
```

### Response Format

```json
{
  "safe": true,
  "threats_detected": [],
  "risk_score": 0.0,
  "pii_detected": null,
  "sanitized_prompt": null,
  "processing_time_ms": 45.23,
  "request_id": "req_1234567890"
}
```

## 🔍 Detection Capabilities

### Prompt Injection Detection
- Vigil TransformerScanner (protectai/deberta-v3-base-prompt-injection)
- Confidence threshold: 0.8

### Jailbreak Pattern Detection
- Developer/Admin mode bypasses
- AIM/Machiavellian persona attacks
- Hypothetical/fictional scenario attacks
- Grandma/emotional manipulation exploits
- Translation bypass attempts
- Context manipulation attacks
- Function/tool call injections
- Authority claim impersonation
- Code execution attempts

### PII Detection (Presidio)
- Email addresses
- Phone numbers
- Credit card numbers
- Social Security Numbers (SSN)
- Passport numbers
- IP addresses
- Bank account numbers
- IBAN codes
- Driver's license numbers
- Cryptocurrency addresses

## 🐳 Docker Deployment

### Build and Run API

```bash
# Build
docker build -t veil-armor:latest .

# Run
docker run -d \
  --name veil-armor \
  -p 8000:8000 \
  -e VEIL_ARMOR_API_KEY=your_key \
  veil-armor:latest
```

### Docker Compose

```bash
docker-compose up -d
```

## 🤖 Chatbot Integration

Veil Armor includes a secure chatbot demo:

```bash
cd chatbot
pip install -r requirements.txt

# Run secure version (with Veil Armor protection)
streamlit run app_secure.py

# Run unsecure version (for comparison)
streamlit run app_unsecure.py
```

## 📊 API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/` | GET | Service info |
| `/health` | GET | Health check |
| `/ready` | GET | Readiness probe |
| `/metrics` | GET | Prometheus metrics |
| `/api/v1/check` | POST | Security analysis |
| `/api/v1/generate` | POST | Secure LLM generation |
| `/api/v1/stats` | GET | Real-time statistics |

## ⚙️ Configuration

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `VEIL_ARMOR_API_KEY` | API authentication key | `veil_armor_secret_key_12345` |
| `VEIL_ARMOR_API_URL` | API base URL | `http://localhost:8000` |
| `GEMINI_API_KEY` | Google Gemini API key | - |
| `HF_TOKEN` | Hugging Face token | - |

## 📁 Project Structure

```
veil-armor/
├── src/
│   └── veil_armor/
│       ├── api/
│       │   └── server.py      # Main API server
│       ├── middleware/        # Security middleware
│       ├── scanners/          # Detection modules
│       ├── security/          # Enterprise security
│       └── utils/             # Utilities
├── chatbot/
│   ├── app_secure.py          # Secured chatbot
│   ├── app_unsecure.py        # Unsecured chatbot
│   └── security_client.py     # API client
├── tests/
│   └── test_zero_day_attacks.py  # Attack test suite
├── kubernetes/
│   └── deployment.yaml        # K8s manifests
├── Dockerfile
├── docker-compose.yml
├── requirements.txt
└── README.md
```

## 🧪 Testing

Run the security test suite:

```bash
cd tests
pytest test_zero_day_attacks.py -v
```

Expected: 42/42 tests passing (100% detection rate)

## 📈 Metrics

Access Prometheus-compatible metrics at `/metrics`:

```
veil_armor_requests_total
veil_armor_requests_blocked
veil_armor_requests_allowed
veil_armor_uptime_seconds
```

## 🔒 Security Best Practices

1. **Always use HTTPS in production**
2. **Rotate API keys regularly**
3. **Enable rate limiting for public endpoints**
4. **Monitor blocked requests for attack patterns**
5. **Keep dependencies updated**

## 📄 License

Apache 2.0

## 🤝 Support

For enterprise support and custom implementations, contact the development team.

---

**Veil Armor** - Protecting your LLM applications from sophisticated attacks.
