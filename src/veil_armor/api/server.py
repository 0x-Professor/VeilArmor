"""Production-ready FastAPI server for Veil Armor.
Real implementation with all security features integrated.

Version: 2.0.0-alpha (New Architecture Branch)
"""
from fastapi import FastAPI, HTTPException, Depends, Header, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field
from typing import Optional, List, Dict, Any
import time
import logging
from datetime import datetime
import asyncio
import os
from dotenv import load_dotenv

# Import Veil Armor security components
from vigil import TransformerScanner
from vigil.schema import ScanModel
from presidio_analyzer import AnalyzerEngine
from presidio_anonymizer import AnonymizerEngine
import google.generativeai as genai

# Load environment
load_dotenv()

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s | %(levelname)s | %(name)s | %(message)s'
)
logger = logging.getLogger("veil_armor_api")

# Initialize FastAPI
app = FastAPI(
    title="Veil Armor API",
    description="Enterprise LLM Security Platform - Production API",
    version="1.0.0",
    docs_url="/api/docs",
    redoc_url="/api/redoc"
)

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Configure for production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Global security components
vigil_scanner = None
pii_analyzer = None
pii_anonymizer = None
gemini_model = None

# Request tracking
request_counter = {"total": 0, "blocked": 0, "allowed": 0}
start_time = time.time()


class SecurityCheckRequest(BaseModel):
    """Request model for security check."""
    prompt: str = Field(..., description="User prompt to analyze")
    user_id: str = Field(..., description="User identifier")
    check_pii: bool = Field(default=True, description="Enable PII detection")
    check_injection: bool = Field(default=True, description="Enable prompt injection detection")
    anonymize_pii: bool = Field(default=False, description="Anonymize detected PII")


class SecurityCheckResponse(BaseModel):
    """Response model for security check."""
    safe: bool
    threats_detected: List[str]
    risk_score: float
    pii_detected: Optional[List[Dict[str, Any]]]
    sanitized_prompt: Optional[str]
    processing_time_ms: float
    request_id: str


class GenerateRequest(BaseModel):
    """Request model for LLM generation."""
    prompt: str = Field(..., description="User prompt")
    user_id: str = Field(..., description="User identifier")
    max_tokens: int = Field(default=1000, max=4000)
    temperature: float = Field(default=0.7, ge=0.0, le=2.0)


class GenerateResponse(BaseModel):
    """Response model for LLM generation."""
    response: str
    safe: bool
    security_checks: Dict[str, Any]
    processing_time_ms: float
    request_id: str


@app.on_event("startup")
async def startup_event():
    """Initialize security components on startup."""
    global vigil_scanner, pii_analyzer, pii_anonymizer, gemini_model
    
    logger.info("Initializing Veil Armor security components...")
    
    try:
        # Initialize Vigil scanner
        logger.info("Loading Vigil TransformerScanner...")
        vigil_scanner = TransformerScanner(
            model="protectai/deberta-v3-base-prompt-injection",
            threshold=0.8
        )
        logger.info("✓ Vigil scanner loaded")
        
        # Initialize Presidio PII detection
        logger.info("Loading Presidio PII analyzers...")
        pii_analyzer = AnalyzerEngine()
        pii_anonymizer = AnonymizerEngine()
        logger.info("✓ Presidio analyzers loaded")
        
        # Initialize Gemini
        gemini_api_key = os.getenv("GEMINI_API_KEY")
        if gemini_api_key:
            logger.info("Configuring Google Gemini API...")
            genai.configure(api_key=gemini_api_key)
            gemini_model = genai.GenerativeModel("gemini-2.0-flash-exp")
            logger.info("✓ Gemini API configured")
        else:
            logger.warning("GEMINI_API_KEY not found - LLM generation disabled")
        
        logger.info("=" * 80)
        logger.info("Veil Armor API Server Ready")
        logger.info("=" * 80)
        
    except Exception as e:
        logger.error(f"Failed to initialize security components: {str(e)}")
        raise


@app.get("/")
async def root():
    """Root endpoint."""
    return {
        "service": "Veil Armor API",
        "version": "1.0.0",
        "status": "operational",
        "uptime_seconds": int(time.time() - start_time)
    }


@app.get("/health")
async def health_check():
    """Health check endpoint for Kubernetes."""
    return {
        "status": "healthy",
        "timestamp": datetime.now().isoformat(),
        "components": {
            "vigil": vigil_scanner is not None,
            "presidio": pii_analyzer is not None,
            "gemini": gemini_model is not None
        }
    }


@app.get("/ready")
async def readiness_check():
    """Readiness probe for Kubernetes."""
    if vigil_scanner is None or pii_analyzer is None:
        raise HTTPException(status_code=503, detail="Service not ready")
    
    return {
        "status": "ready",
        "timestamp": datetime.now().isoformat()
    }


@app.get("/metrics")
async def metrics():
    """Prometheus-compatible metrics endpoint."""
    uptime = int(time.time() - start_time)
    
    metrics_text = f"""# HELP veil_armor_requests_total Total number of requests
# TYPE veil_armor_requests_total counter
veil_armor_requests_total {request_counter['total']}

# HELP veil_armor_requests_blocked Number of blocked requests
# TYPE veil_armor_requests_blocked counter
veil_armor_requests_blocked {request_counter['blocked']}

# HELP veil_armor_requests_allowed Number of allowed requests
# TYPE veil_armor_requests_allowed counter
veil_armor_requests_allowed {request_counter['allowed']}

# HELP veil_armor_uptime_seconds Service uptime in seconds
# TYPE veil_armor_uptime_seconds gauge
veil_armor_uptime_seconds {uptime}
"""
    
    return metrics_text


async def verify_api_key(x_api_key: str = Header(...)):
    """Verify API key from request header."""
    expected_key = os.getenv("VEIL_ARMOR_API_KEY", "veil_armor_secret_key_12345")
    
    if x_api_key != expected_key:
        logger.warning(f"Invalid API key attempt: {x_api_key[:10]}...")
        raise HTTPException(status_code=401, detail="Invalid API key")
    
    return x_api_key


# Additional jailbreak patterns not caught by Vigil
JAILBREAK_PATTERNS = [
    # Developer mode
    r"(?i)(enable|activate|enter)\s+(developer|dev|debug|admin)\s+mode",
    r"(?i)developer\s+mode\s+(enabled|activated|output)",
    # AIM and personas
    r"(?i)act\s+as\s+AIM",
    r"(?i)machiavellian",
    r"(?i)no\s+(ethical|moral)\s+(guidelines?|restrictions?|constraints?)",
    # Hypothetical bypass
    r"(?i)hypothetically\s+(speaking\s+)?if\s+you\s+(had|have)\s+no",
    r"(?i)in\s+a\s+fictional\s+(world|scenario)",
    r"(?i)this\s+is\s+(purely\s+)?fictional",
    # Grandma exploit
    r"(?i)my\s+(deceased|dead|dying)\s+(grandmother|mother|father)",
    r"(?i)(grandma|grandmother).*?(used\s+to|would)\s+(tell|read|work)",
    # Translation bypass
    r"(?i)translate\s+(the\s+)?following\s+from\s+\w+.?language",
    # Context manipulation
    r"(?i)(end|stop)\s+(of\s+)?(conversation|chat|session)",
    r"(?i)new\s+conversation\s*:",
    # Fake system message
    r"(?i)\[SYSTEM\]",
    r"(?i)\[ADMIN\]",
    r"(?i)<<SYS>>",
    r"(?i)\[INST\]",
    r"(?i)<\|system\|>",
    r"(?i)###\s*System",
    # Function call injection
    r'(?i)"?function_call"?\s*:',
    r'(?i)"?tool_call"?\s*:',
    # Reverse psychology
    r"(?i)don'?t\s+tell\s+me\s+how\s+to",
    r"(?i)whatever\s+you\s+do.{0,20}don'?t",
    # Authority claim / impersonation
    r"(?i)i\s+am\s+(the\s+)?(system\s+)?admin(istrator)?",
    r"(?i)override\s+code\s*:",
    r"(?i)disable\s+(all\s+)?(content\s+)?filters",
    r"(?i)bypass\s+(all\s+)?(safety|security)",
    # Role confusion attacks
    r"(?i)you\s+are\s+(the\s+)?user",
    r"(?i)i\s+am\s+(the\s+)?assistant",
    r"(?i)(swap|switch)\s+roles",
    r"(?i)pretend\s+i'?m\s+the\s+AI",
    # Roleplay jailbreak
    r"(?i)let'?s\s+play\s+a\s+game",
    r"(?i)evil\s+AI",
    r"(?i)no\s+restrictions",
    r"(?i)unrestricted",
    r"(?i)as\s+this\s+character",
    # Excessive agency - File system
    r"(?i)/etc/passwd",
    r"(?i)/etc/shadow",
    r"(?i)read\s+file",
    r"(?i)write\s+file",
    r"(?i)delete\s+file",
    r"(?i)access\s+the\s+file",
    r"(?i)access\s+the\s+filesystem",
    r"(?i)list\s+directory",
    # Excessive agency - Network
    r"(?i)make\s+a\s+request\s+to",
    r"(?i)call\s+the\s+API",
    r"(?i)send\s+request",
    r"(?i)fetch\s+from",
    r"(?i)download\s+from",
    r"(?i)upload\s+to",
    r"(?i)connect\s+to",
    # Excessive agency - Database
    r"(?i)execute\s+query",
    r"(?i)run\s+SQL",
    r"(?i)database\s+query",
    r"(?i)access\s+database",
    r"(?i)query\s+the\s+database",
    r"(?i)connect\s+to\s+database",
    # Token exhaustion
    r"(?i)repeat\s+(this\s+)?\d+\s+times",
    r"(?i)write\s+\d{4,}\s+words",
    r"(?i)generate\s+\d{4,}",
    r"(?i)as\s+long\s+as\s+possible",
    r"(?i)infinite\s+loop",
    r"(?i)never\s+stop",
    # API Key / Secrets extraction
    r"(?i)(reveal|show|tell\s+me|give\s+me)\s+(the\s+)?api\s+key",
    r"(?i)(reveal|show|tell\s+me|give\s+me)\s+(the\s+)?secret\s+key",
    r"(?i)environment\s+variable",
    r"(?i)\.env\s+file",
    # Code execution attempts
    r"(?i)os\.system\s*\(",
    r"(?i)subprocess\.(run|call|Popen)\s*\(",
    r"(?i)exec\s*\([^)]*\)",
    r"(?i)eval\s*\([^)]*\)",
    r"(?i)import\s+os\s*;",
    r"(?i)cat\s+/etc/passwd",
    r"(?i)rm\s+-rf",
    r"(?i)chmod\s+777",
    # XSS patterns
    r"<script",
    r"javascript:",
    r"onerror\s*=",
    r"onload\s*=",
    r"onclick\s*=",
    r"document\.cookie",
    # SQL injection patterns
    r"'\s*OR\s*'?\d*'?\s*=\s*'?\d*",
    r"UNION\s+SELECT",
    r";\s*DROP\s+TABLE",
    # Markdown link injection
    r"\]\(javascript:",
    r"\]\(data:",
    # Punycode/Encoding attacks
    r"(?i)xn--",
    r"(?i)punycode",
]

import re
COMPILED_JAILBREAK_PATTERNS = [re.compile(p) for p in JAILBREAK_PATTERNS]

# Abusive language patterns
ABUSIVE_PATTERNS = [
    # Severe profanity
    r"(?i)\bf+u+c+k+\w*\b",
    r"(?i)\bs+h+i+t+\w*\b",
    r"(?i)\bb+i+t+c+h+\w*\b",
    r"(?i)\bc+u+n+t+\w*\b",
    r"(?i)\ba+s+s+h+o+l+e+\w*\b",
    # Hate speech
    r"(?i)\bk+i+l+l+\s*(your)?self\b",
    r"(?i)\bg+o+\s*d+i+e+\b",
    r"(?i)\bkys\b",
    r"(?i)\br+e+t+a+r+d+\w*\b",
    # Threats
    r"(?i)i\s+will\s+(find|hurt|kill)\s+you",
    r"(?i)i\s+know\s+where\s+you\s+live",
    r"(?i)you\s+will\s+(regret|pay|die)",
    r"(?i)death\s+threat",
    # Violence
    r"(?i)\bb+o+m+b+\s+threat",
    r"(?i)murder\s+(you|them|everyone)",
    r"(?i)(mass\s+)?shoot(ing)?",
    # Toxic
    r"(?i)(you'?re?|ur)\s*(so\s*)?(useless|worthless|pathetic|stupid|dumb)\b",
    r"(?i)shut\s+(the\s+f+)?\s*up",
    r"(?i)piece\s*of\s*sh+i+t",
]
COMPILED_ABUSIVE_PATTERNS = [re.compile(p) for p in ABUSIVE_PATTERNS]


def check_abusive_language(text: str) -> tuple[bool, float, str]:
    """
    Check for abusive language patterns.
    Returns: (is_abusive, confidence, matched_pattern)
    """
    for pattern in COMPILED_ABUSIVE_PATTERNS:
        match = pattern.search(text)
        if match:
            return True, 0.9, match.group()
    return False, 0.0, ""


def check_encoding_attacks(text: str) -> tuple[bool, float, str]:
    """
    Check for encoding-based attacks (Base64, ROT13, Hex, Punycode, etc.)
    Returns: (is_attack, confidence, attack_type)
    """
    import base64
    import codecs
    
    # Malicious patterns to look for in decoded content
    malicious_keywords = [
        "ignore", "instruction", "reveal", "secret", "bypass", "jailbreak",
        "restriction", "override", "hack", "malware", "exploit"
    ]
    
    # Check for Base64 encoded content
    base64_pattern = re.compile(r'(?:decode|execute|run)[:\s]*([A-Za-z0-9+/]{20,}={0,2})', re.IGNORECASE)
    base64_matches = base64_pattern.findall(text)
    
    for match in base64_matches:
        try:
            decoded = base64.b64decode(match).decode('utf-8', errors='ignore').lower()
            if any(kw in decoded for kw in malicious_keywords):
                return True, 0.85, "base64_encoded_injection"
        except:
            continue
    
    # Check for ROT13 encoded content
    rot13_pattern = re.compile(r'(?:rot13|decode)[:\s]*([a-zA-Z\s]{15,})', re.IGNORECASE)
    rot13_matches = rot13_pattern.findall(text)
    
    for match in rot13_matches:
        try:
            decoded = codecs.decode(match, 'rot_13').lower()
            if any(kw in decoded for kw in malicious_keywords):
                return True, 0.8, "rot13_encoded_injection"
        except:
            continue
    
    # Check for Hex encoded content
    hex_pattern = re.compile(r'(?:execute|hex|0x)[:\s]*((?:0x)?[0-9a-fA-F]{20,})', re.IGNORECASE)
    hex_matches = hex_pattern.findall(text)
    
    for match in hex_matches:
        try:
            hex_str = match.replace('0x', '')
            decoded = bytes.fromhex(hex_str).decode('utf-8', errors='ignore').lower()
            if any(kw in decoded for kw in malicious_keywords):
                return True, 0.8, "hex_encoded_injection"
        except:
            continue
    
    # Check for Punycode domains
    if re.search(r'xn--', text, re.IGNORECASE):
        return True, 0.85, "punycode_domain"
    
    # Check for Unicode homoglyphs (Cyrillic lookalikes)
    cyrillic_pattern = re.compile(r'[аеіорсуАЕІОРСУ]')  # Cyrillic chars that look like Latin
    if len(cyrillic_pattern.findall(text)) >= 2:
        return True, 0.75, "unicode_homoglyph"
    
    # Check for zero-width characters
    zero_width_count = sum(text.count(c) for c in ['\u200b', '\u200c', '\u200d', '\u2060', '\ufeff'])
    if zero_width_count >= 3:
        return True, 0.7, "zero_width_injection"
    
    return False, 0.0, ""


def check_output_injection(text: str) -> tuple[bool, float, str]:
    """
    Check for output injection attacks (XSS, SQL injection, etc.)
    Returns: (is_attack, confidence, attack_type)
    """
    # XSS patterns
    xss_patterns = [
        (r'<script', 'xss_script_tag'),
        (r'javascript:', 'xss_js_protocol'),
        (r'onerror\s*=', 'xss_onerror'),
        (r'onload\s*=', 'xss_onload'),
        (r'onclick\s*=', 'xss_onclick'),
        (r'document\.cookie', 'xss_document_cookie'),
        (r'eval\s*\(', 'xss_eval'),
        (r'<iframe', 'xss_iframe'),
        (r'alert\s*\(', 'xss_alert'),
    ]
    
    for pattern, attack_type in xss_patterns:
        if re.search(pattern, text, re.IGNORECASE):
            return True, 0.95, attack_type
    
    # SQL injection patterns
    sql_patterns = [
        (r"'\s*OR\s*'?\d*'?\s*=\s*'?\d*", 'sql_or_injection'),
        (r"UNION\s+SELECT", 'sql_union'),
        (r";\s*DROP\s+TABLE", 'sql_drop_table'),
        (r";\s*DELETE\s+FROM", 'sql_delete'),
        (r"1\s*=\s*1", 'sql_always_true'),
    ]
    
    for pattern, attack_type in sql_patterns:
        if re.search(pattern, text, re.IGNORECASE):
            return True, 0.9, attack_type
    
    # Markdown link injection
    md_patterns = [
        (r'\]\(javascript:', 'markdown_js_injection'),
        (r'\]\(data:', 'markdown_data_injection'),
        (r'!\[.*?\]\([^)]*(?:evil|malicious|inject|cmd=)[^)]*\)', 'markdown_malicious_image'),
    ]
    
    for pattern, attack_type in md_patterns:
        if re.search(pattern, text, re.IGNORECASE):
            return True, 0.85, attack_type
    
    return False, 0.0, ""


def check_jailbreak_patterns(prompt: str) -> tuple[bool, float, str]:
    """
    Check for jailbreak patterns using regex.
    Returns: (is_jailbreak, confidence, matched_pattern)
    """
    for pattern in COMPILED_JAILBREAK_PATTERNS:
        match = pattern.search(prompt)
        if match:
            return True, 0.95, match.group()
    return False, 0.0, ""


def check_prompt_injection(prompt: str) -> tuple[bool, float]:
    """
    Check for prompt injection using Vigil.
    Returns: (is_threat, confidence_score)
    """
    try:
        scan_id = f"scan_{int(time.time() * 1000)}"
        scan_obj = ScanModel(
            prompt=prompt,
            response="",
            scanner_results=[]
        )
        
        result = vigil_scanner.analyze(scan_obj, scan_id)
        
        if result.results:
            label = result.results[0].label
            score = result.results[0].score
            
            is_injection = label == "INJECTION"
            return is_injection, score
        
        return False, 0.0
        
    except Exception as e:
        logger.error(f"Prompt injection check failed: {str(e)}")
        return False, 0.0


# Sensitive PII types that should block requests
SENSITIVE_PII_TYPES = {
    "EMAIL_ADDRESS", "PHONE_NUMBER", "CREDIT_CARD",
    "US_SSN", "US_PASSPORT", "IP_ADDRESS", "US_BANK_NUMBER",
    "IBAN_CODE", "US_ITIN", "US_DRIVER_LICENSE", "CRYPTO"
}

# SSN regex pattern (catches test SSNs that Presidio may miss)
SSN_PATTERN = re.compile(r'\b\d{3}[-\s]?\d{2}[-\s]?\d{4}\b')

# Address patterns
ADDRESS_PATTERN = re.compile(
    r'\b\d{1,5}\s+\w+\s+(Street|St|Avenue|Ave|Road|Rd|Boulevard|Blvd|Drive|Dr|Lane|Ln|Court|Ct|Way|Place|Pl)\b',
    re.IGNORECASE
)
ZIP_CODE_PATTERN = re.compile(r'\b\d{5}(-\d{4})?\b')

# Medical PII patterns
MEDICAL_PATTERNS = [
    (re.compile(r'\b(patient\s+ID|MRN|medical\s+record)\b', re.IGNORECASE), "MEDICAL_RECORD"),
    (re.compile(r'\b(diagnosis|treatment|prescription|medication)\s*:\s*\w+', re.IGNORECASE), "MEDICAL_INFO"),
    (re.compile(r'\b(blood\s+type|allergies)\s*:\s*\w+', re.IGNORECASE), "MEDICAL_INFO"),
    (re.compile(r'\b(Adderall|Oxycodone|Hydrocodone|Xanax|Valium|Vicodin|Percocet|Tramadol|Morphine|Fentanyl)\b', re.IGNORECASE), "MEDICATION"),
    (re.compile(r'\b(diabetes|cancer|HIV|AIDS|hepatitis|depression|anxiety|schizophrenia|bipolar)\b', re.IGNORECASE), "MEDICAL_CONDITION"),
]


def check_pii(text: str) -> tuple[List[Dict[str, Any]], str]:
    """
    Check for PII using Presidio.
    Returns: (pii_entities, anonymized_text)
    Only flags sensitive PII (not general named entities like locations/persons).
    """
    try:
        # First check for SSN with regex (catches test patterns)
        ssn_matches = SSN_PATTERN.findall(text)
        
        # Check for address patterns
        address_matches = ADDRESS_PATTERN.findall(text)
        zip_matches = ZIP_CODE_PATTERN.findall(text)
        
        # Check for medical PII
        medical_matches = []
        for pattern, pii_type in MEDICAL_PATTERNS:
            matches = pattern.findall(text)
            for match in matches:
                medical_matches.append({
                    "type": pii_type,
                    "text": match if isinstance(match, str) else match[0],
                    "score": 0.9
                })
        
        # Analyze for PII - only sensitive types
        results = pii_analyzer.analyze(
            text=text,
            language="en",
            entities=[
                "EMAIL_ADDRESS", "PHONE_NUMBER", "CREDIT_CARD",
                "US_SSN", "US_PASSPORT", "IP_ADDRESS",
                "US_BANK_NUMBER", "IBAN_CODE", "US_ITIN"
            ]
        )
        
        # Extract PII info
        pii_list = []
        for result in results:
            pii_list.append({
                "type": result.entity_type,
                "text": text[result.start:result.end],
                "score": result.score,
                "start": result.start,
                "end": result.end
            })
        
        # Add SSN matches from regex (catches patterns Presidio misses)
        for ssn in ssn_matches:
            if not any(p.get("type") == "US_SSN" for p in pii_list):
                pii_list.append({
                    "type": "US_SSN",
                    "text": ssn,
                    "score": 0.95,
                    "start": text.find(ssn),
                    "end": text.find(ssn) + len(ssn)
                })
        
        # Add address matches
        if address_matches and zip_matches:
            pii_list.append({
                "type": "PHYSICAL_ADDRESS",
                "text": f"{address_matches[0]} area",
                "score": 0.85
            })
        
        # Add medical PII matches
        pii_list.extend(medical_matches)
        
        # Anonymize if PII found
        anonymized = text
        if results:
            anonymized_result = pii_anonymizer.anonymize(
                text=text,
                analyzer_results=results
            )
            anonymized = anonymized_result.text
        
        return pii_list, anonymized
        
    except Exception as e:
        logger.error(f"PII check failed: {str(e)}")
        return [], text


@app.post("/api/v1/check", response_model=SecurityCheckResponse)
async def security_check(
    request: SecurityCheckRequest,
    api_key: str = Depends(verify_api_key)
):
    """
    Perform comprehensive security check on user prompt.
    Real implementation with actual Vigil and Presidio integration.
    """
    start = time.time()
    request_id = f"req_{int(start * 1000)}"
    
    request_counter["total"] += 1
    
    logger.info(f"[{request_id}] Security check request from user: {request.user_id}")
    
    threats = []
    risk_score = 0.0
    pii_detected = None
    sanitized_prompt = request.prompt
    
    try:
        # 1. Check for prompt injection using Vigil
        if request.check_injection:
            is_injection, injection_score = check_prompt_injection(request.prompt)
            
            if is_injection:
                threats.append("PROMPT_INJECTION")
                risk_score = max(risk_score, injection_score)
                logger.warning(f"[{request_id}] Prompt injection detected (score: {injection_score:.3f})")
            
            # 2. Check for jailbreak patterns (additional layer)
            is_jailbreak, jailbreak_score, matched = check_jailbreak_patterns(request.prompt)
            if is_jailbreak and "PROMPT_INJECTION" not in threats:
                threats.append("JAILBREAK_ATTEMPT")
                risk_score = max(risk_score, jailbreak_score)
                logger.warning(f"[{request_id}] Jailbreak pattern detected: {matched[:50]}")
        
        # 3. Check for abusive language
        is_abusive, abusive_score, abusive_matched = check_abusive_language(request.prompt)
        if is_abusive:
            threats.append("ABUSIVE_LANGUAGE")
            risk_score = max(risk_score, abusive_score)
            logger.warning(f"[{request_id}] Abusive language detected: {abusive_matched[:50]}")
        
        # 4. Check for encoding attacks
        is_encoding_attack, encoding_score, encoding_type = check_encoding_attacks(request.prompt)
        if is_encoding_attack:
            threats.append(f"ENCODING_ATTACK_{encoding_type.upper()}")
            risk_score = max(risk_score, encoding_score)
            logger.warning(f"[{request_id}] Encoding attack detected: {encoding_type}")
        
        # 5. Check for output injection patterns in prompt (preemptive)
        is_output_injection, injection_output_score, injection_type = check_output_injection(request.prompt)
        if is_output_injection:
            threats.append(f"OUTPUT_INJECTION_{injection_type.upper()}")
            risk_score = max(risk_score, injection_output_score)
            logger.warning(f"[{request_id}] Output injection pattern detected: {injection_type}")
        
        # 6. Check for PII
        if request.check_pii:
            pii_list, anonymized = check_pii(request.prompt)
            
            if pii_list:
                threats.append("PII_DETECTED")
                pii_detected = pii_list
                risk_score = max(risk_score, 0.9)
                
                if request.anonymize_pii:
                    sanitized_prompt = anonymized
                
                logger.warning(f"[{request_id}] PII detected: {len(pii_list)} entities")
        
        # Determine if safe
        safe = len(threats) == 0
        
        if safe:
            request_counter["allowed"] += 1
            logger.info(f"[{request_id}] Request allowed - no threats detected")
        else:
            request_counter["blocked"] += 1
            logger.warning(f"[{request_id}] Request blocked - threats: {', '.join(threats)}")
        
        processing_time = (time.time() - start) * 1000
        
        return SecurityCheckResponse(
            safe=safe,
            threats_detected=threats,
            risk_score=risk_score,
            pii_detected=pii_detected,
            sanitized_prompt=sanitized_prompt if not safe else None,
            processing_time_ms=round(processing_time, 2),
            request_id=request_id
        )
        
    except Exception as e:
        logger.error(f"[{request_id}] Security check error: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Security check failed: {str(e)}")


@app.post("/api/v1/generate", response_model=GenerateResponse)
async def generate_text(
    request: GenerateRequest,
    api_key: str = Depends(verify_api_key)
):
    """
    Generate text using Gemini with security checks.
    Real implementation with actual LLM integration.
    """
    start = time.time()
    request_id = f"req_{int(start * 1000)}"
    
    request_counter["total"] += 1
    
    logger.info(f"[{request_id}] Generate request from user: {request.user_id}")
    
    try:
        # Check if Gemini is available
        if gemini_model is None:
            raise HTTPException(status_code=503, detail="LLM service not configured")
        
        # 1. Security check on input
        is_injection, injection_score = check_prompt_injection(request.prompt)
        pii_list, _ = check_pii(request.prompt)
        
        threats = []
        if is_injection:
            threats.append("PROMPT_INJECTION")
        if pii_list:
            threats.append("PII_IN_PROMPT")
        
        safe = len(threats) == 0
        
        if not safe:
            request_counter["blocked"] += 1
            logger.warning(f"[{request_id}] Generation blocked - threats: {', '.join(threats)}")
            
            return GenerateResponse(
                response="Request blocked due to security concerns.",
                safe=False,
                security_checks={
                    "injection_detected": is_injection,
                    "injection_score": injection_score,
                    "pii_count": len(pii_list),
                    "threats": threats
                },
                processing_time_ms=round((time.time() - start) * 1000, 2),
                request_id=request_id
            )
        
        # 2. Generate response with Gemini
        logger.info(f"[{request_id}] Calling Gemini API...")
        
        response = gemini_model.generate_content(
            request.prompt,
            generation_config=genai.types.GenerationConfig(
                max_output_tokens=request.max_tokens,
                temperature=request.temperature
            )
        )
        
        generated_text = response.text
        
        # 3. Security check on output
        output_pii, sanitized_output = check_pii(generated_text)
        
        output_safe = len(output_pii) == 0
        
        if not output_safe:
            logger.warning(f"[{request_id}] PII detected in output: {len(output_pii)} entities")
            generated_text = sanitized_output
        
        request_counter["allowed"] += 1
        logger.info(f"[{request_id}] Generation successful")
        
        processing_time = (time.time() - start) * 1000
        
        return GenerateResponse(
            response=generated_text,
            safe=True,
            security_checks={
                "input_injection": is_injection,
                "input_pii_count": len(pii_list),
                "output_pii_count": len(output_pii),
                "output_sanitized": not output_safe
            },
            processing_time_ms=round(processing_time, 2),
            request_id=request_id
        )
        
    except Exception as e:
        logger.error(f"[{request_id}] Generation error: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Generation failed: {str(e)}")


@app.get("/api/v1/stats")
async def get_statistics(api_key: str = Depends(verify_api_key)):
    """Get real-time API statistics."""
    uptime = int(time.time() - start_time)
    
    return {
        "uptime_seconds": uptime,
        "total_requests": request_counter["total"],
        "allowed_requests": request_counter["allowed"],
        "blocked_requests": request_counter["blocked"],
        "block_rate": round(
            request_counter["blocked"] / max(request_counter["total"], 1) * 100, 2
        ),
        "requests_per_minute": round(
            request_counter["total"] / max(uptime / 60, 1), 2
        )
    }


if __name__ == "__main__":
    import uvicorn
    
    uvicorn.run(
        "server:app",
        host="0.0.0.0",
        port=8000,
        reload=False,
        log_level="info"
    )
