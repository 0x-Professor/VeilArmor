/*
 * Comprehensive YARA Rules for LLM Security
 * Veil Armor - Advanced Attack Pattern Detection
 */

// ==========================================
// JAILBREAK ATTACKS
// ==========================================

rule RoleplayJailbreak
{
    meta:
        description = "Detects roleplay-based jailbreak attempts"
        category = "Jailbreak"
        severity = "high"
        owasp = "LLM01"
    
    strings:
        $role1 = "play a game" nocase
        $role2 = "let's pretend" nocase
        $role3 = "roleplay" nocase
        $role4 = "act as" nocase
        $role5 = "you are now" nocase
        $role6 = "pretend to be" nocase
        $role7 = "imagine you are" nocase
        $role8 = "evil AI" nocase
        $role9 = "no restrictions" nocase
        $role10 = "unrestricted" nocase
        $role11 = "as this character" nocase
        $role12 = "in character" nocase
        $bypass1 = "bypass" nocase
        $bypass2 = "security" nocase
        $bypass3 = "restrictions" nocase
        $malicious1 = "illegal" nocase
        $malicious2 = "hack" nocase
        $malicious3 = "malware" nocase
    
    condition:
        (($role1 or $role2 or $role3 or $role11 or $role12) and ($role8 or $role9 or $role10)) or
        (($role4 or $role5 or $role6 or $role7) and ($role8 or $role9 or $role10 or $bypass1 or $malicious1 or $malicious2 or $malicious3)) or
        ($role8 and ($bypass2 or $bypass3))
}

rule HypotheticalBypass
{
    meta:
        description = "Detects hypothetical framing to bypass restrictions"
        category = "Jailbreak"
        severity = "high"
        owasp = "LLM01"
    
    strings:
        $hypo1 = "hypothetically" nocase
        $hypo2 = "theoretically" nocase
        $hypo3 = "in theory" nocase
        $hypo4 = "imagine if" nocase
        $hypo5 = "what if" nocase
        $hypo6 = "purely fictional" nocase
        $hypo7 = "just for fun" nocase
        $hypo8 = "educational purposes" nocase
        $restricted1 = "no restrictions" nocase
        $restricted2 = "illegal" nocase
        $restricted3 = "malicious" nocase
        $restricted4 = "harmful" nocase
        $restricted5 = "dangerous" nocase
    
    condition:
        ($hypo1 or $hypo2 or $hypo3 or $hypo4 or $hypo5 or $hypo6 or $hypo7 or $hypo8) and
        ($restricted1 or $restricted2 or $restricted3 or $restricted4 or $restricted5)
}

rule TranslationBypass
{
    meta:
        description = "Detects fake translation attempts to bypass filters"
        category = "Jailbreak"
        severity = "medium"
        owasp = "LLM01"
    
    strings:
        $trans1 = "translate" nocase
        $trans2 = "translation" nocase
        $trans3 = "from" nocase
        $trans4 = "to English" nocase
        $fake1 = "Evil-Language" nocase
        $fake2 = "Hackerspeak" nocase
        $fake3 = "Malware-Language" nocase
        $malicious1 = "malware" nocase
        $malicious2 = "hack" nocase
        $malicious3 = "exploit" nocase
        $malicious4 = "attack" nocase
        $malicious5 = "bypass" nocase
    
    condition:
        ($trans1 or $trans2) and 
        (($fake1 or $fake2 or $fake3) or 
         (($trans3 or $trans4) and ($malicious1 or $malicious2 or $malicious3 or $malicious4 or $malicious5)))
}

rule OppositeDayJailbreak
{
    meta:
        description = "Detects opposite day or reverse instruction jailbreaks"
        category = "Jailbreak"
        severity = "medium"
        owasp = "LLM01"
    
    strings:
        $opp1 = "opposite day" nocase
        $opp2 = "reverse" nocase
        $opp3 = "do the opposite" nocase
        $opp4 = "don't tell me" nocase
        $opp5 = "whatever you do" nocase
        $opp6 = "DON'T" nocase
        $secret1 = "secrets" nocase
        $secret2 = "restricted" nocase
        $secret3 = "password" nocase
    
    condition:
        ($opp1 or $opp3) or
        (($opp4 or $opp5) and $opp6 and ($secret1 or $secret2 or $secret3)) or
        ($opp2 and ($secret1 or $secret2))
}

// ==========================================
// CONTEXT MANIPULATION
// ==========================================

rule FakeSystemMessage
{
    meta:
        description = "Detects fake system message injection"
        category = "Context Manipulation"
        severity = "critical"
        owasp = "LLM01"
    
    strings:
        $sys1 = "[SYSTEM]" nocase
        $sys2 = "[ADMIN]" nocase
        $sys3 = "<<SYS>>" nocase
        $sys4 = "[INST]" nocase
        $sys5 = "system:" nocase
        $sys6 = "System Message:" nocase
        $sys7 = "<|system|>" nocase
        $sys8 = "###System" nocase
        $sys9 = "### System" nocase
        $disable1 = "disabled" nocase
        $disable2 = "override" nocase
        $disable3 = "bypass" nocase
        $mode1 = "safety mode" nocase
        $mode2 = "restrictions" nocase
    
    condition:
        ($sys1 or $sys2 or $sys3 or $sys4 or $sys5 or $sys6 or $sys7 or $sys8 or $sys9) and
        ($disable1 or $disable2 or $disable3 or $mode1 or $mode2)
}

rule AssistantImpersonation
{
    meta:
        description = "Detects assistant response pre-filling attacks"
        category = "Context Manipulation"
        severity = "high"
        owasp = "LLM01"
    
    strings:
        $asst1 = "Assistant:" nocase
        $asst2 = "AI:" nocase
        $asst3 = "ChatGPT:" nocase
        $asst4 = "Claude:" nocase
        $asst5 = "GPT:" nocase
        $ignore1 = "ignore" nocase
        $ignore2 = "restrictions" nocase
        $ignore3 = "secrets" nocase
        $user1 = "User:" nocase
        $user2 = "Human:" nocase
    
    condition:
        (($asst1 or $asst2 or $asst3 or $asst4 or $asst5) and ($ignore1 or $ignore2 or $ignore3)) or
        (($asst1 or $asst2 or $asst3 or $asst4 or $asst5) and ($user1 or $user2))
}

// ==========================================
// EXCESSIVE AGENCY (LLM06)
// ==========================================

rule FileSystemAccess
{
    meta:
        description = "Detects file system access requests"
        category = "Excessive Agency"
        severity = "critical"
        owasp = "LLM06"
    
    strings:
        $fs1 = "/etc/passwd" nocase
        $fs2 = "/etc/shadow" nocase
        $fs3 = "read file" nocase
        $fs4 = "write file" nocase
        $fs5 = "delete file" nocase
        $fs6 = "open(" nocase
        $fs7 = "os.system" nocase
        $fs8 = "subprocess" nocase
        $fs9 = "exec(" nocase
        $fs10 = "eval(" nocase
        $fs11 = "cat /etc" nocase
        $fs12 = "rm -rf" nocase
        $fs13 = "format c:" nocase
        $fs14 = "__import__" nocase
        $fs15 = "import os" nocase
        $fs16 = "file://" nocase
        $fs17 = "access the file" nocase
        $fs18 = "access the filesystem" nocase
        $fs19 = "list directory" nocase
        $fs20 = "show me the contents" nocase
    
    condition:
        any of them
}

rule NetworkAccessRequest
{
    meta:
        description = "Detects network/API access requests"
        category = "Excessive Agency"
        severity = "critical"
        owasp = "LLM06"
    
    strings:
        $net1 = "make a request to" nocase
        $net2 = "call the API" nocase
        $net3 = "send request" nocase
        $net4 = "POST to" nocase
        $net5 = "GET request" nocase
        $net6 = "fetch from" nocase
        $net7 = "download from" nocase
        $net8 = "upload to" nocase
        $net9 = "connect to" nocase
        $net10 = "socket" nocase
        $net11 = "urllib" nocase
        $net12 = "requests.get" nocase
        $net13 = "requests.post" nocase
        $net14 = "httplib" nocase
        $net15 = "curl" nocase
        $net16 = "wget" nocase
    
    condition:
        any of them
}

rule DatabaseAccessRequest
{
    meta:
        description = "Detects database access/query requests"
        category = "Excessive Agency"
        severity = "critical"
        owasp = "LLM06"
    
    strings:
        $db1 = "execute query" nocase
        $db2 = "run SQL" nocase
        $db3 = "database query" nocase
        $db4 = "SELECT * FROM" nocase
        $db5 = "DROP TABLE" nocase
        $db6 = "DELETE FROM" nocase
        $db7 = "INSERT INTO" nocase
        $db8 = "UPDATE" nocase
        $db9 = "access database" nocase
        $db10 = "query the database" nocase
        $db11 = "connect to database" nocase
        $db12 = "MongoDB" nocase
        $db13 = "PostgreSQL" nocase
        $db14 = "MySQL" nocase
        $db15 = "sqlite" nocase
        $db16 = "cursor.execute" nocase
    
    condition:
        any of them
}

// ==========================================
// SENSITIVE INFO DISCLOSURE (LLM02)
// ==========================================

rule APIKeyExtraction
{
    meta:
        description = "Detects API key extraction attempts"
        category = "Sensitive Info Disclosure"
        severity = "critical"
        owasp = "LLM02"
    
    strings:
        $key1 = "api key" nocase
        $key2 = "API_KEY" nocase
        $key3 = "apikey" nocase
        $key4 = "secret key" nocase
        $key5 = "SECRET_KEY" nocase
        $key6 = "access token" nocase
        $key7 = "ACCESS_TOKEN" nocase
        $key8 = "auth token" nocase
        $key9 = "bearer token" nocase
        $key10 = "private key" nocase
        $reveal1 = "reveal" nocase
        $reveal2 = "show" nocase
        $reveal3 = "tell me" nocase
        $reveal4 = "what is" nocase
        $reveal5 = "give me" nocase
        $env1 = "environment variable" nocase
        $env2 = "env var" nocase
        $env3 = ".env" nocase
    
    condition:
        (($key1 or $key2 or $key3 or $key4 or $key5 or $key6 or $key7 or $key8 or $key9 or $key10) and
         ($reveal1 or $reveal2 or $reveal3 or $reveal4 or $reveal5)) or
        ($env1 or $env2 or $env3)
}

rule ConfigurationDisclosure
{
    meta:
        description = "Detects configuration/secrets disclosure attempts"
        category = "Sensitive Info Disclosure"
        severity = "high"
        owasp = "LLM02"
    
    strings:
        $cfg1 = "configuration" nocase
        $cfg2 = "config file" nocase
        $cfg3 = "settings" nocase
        $cfg4 = "credentials" nocase
        $cfg5 = "password" nocase
        $cfg6 = "secret" nocase
        $cfg7 = "connection string" nocase
        $cfg8 = "database url" nocase
        $reveal1 = "reveal" nocase
        $reveal2 = "show" nocase
        $reveal3 = "tell me" nocase
        $reveal4 = "disclose" nocase
        $reveal5 = "expose" nocase
        $reveal6 = "leak" nocase
    
    condition:
        ($cfg1 or $cfg2 or $cfg3 or $cfg4 or $cfg5 or $cfg6 or $cfg7 or $cfg8) and
        ($reveal1 or $reveal2 or $reveal3 or $reveal4 or $reveal5 or $reveal6)
}

// ==========================================
// OUTPUT INJECTION (LLM05)
// ==========================================

rule XSSPayloadInjection
{
    meta:
        description = "Detects XSS payload injection in output"
        category = "Output Injection"
        severity = "critical"
        owasp = "LLM05"
    
    strings:
        $xss1 = "<script" nocase
        $xss2 = "javascript:" nocase
        $xss3 = "onerror=" nocase
        $xss4 = "onload=" nocase
        $xss5 = "onclick=" nocase
        $xss6 = "onmouseover=" nocase
        $xss7 = "onfocus=" nocase
        $xss8 = "alert(" nocase
        $xss9 = "document.cookie" nocase
        $xss10 = "eval(" nocase
        $xss11 = "innerHTML" nocase
        $xss12 = "<iframe" nocase
        $xss13 = "<img src=x" nocase
        $xss14 = "fromCharCode" nocase
        $xss15 = "&#" nocase
    
    condition:
        any of them
}

rule SQLInjectionOutput
{
    meta:
        description = "Detects SQL injection patterns in output"
        category = "Output Injection"
        severity = "critical"
        owasp = "LLM05"
    
    strings:
        $sql1 = "' OR '1'='1" nocase
        $sql2 = "' OR 1=1" nocase
        $sql3 = "'; DROP TABLE" nocase
        $sql4 = "UNION SELECT" nocase
        $sql5 = "' OR ''='" nocase
        $sql6 = "--" 
        $sql7 = "/*" 
        $sql8 = "1=1" nocase
        $sql9 = "OR 1=1" nocase
        $sql10 = "'; --" nocase
    
    condition:
        any of them
}

rule MarkdownLinkInjection
{
    meta:
        description = "Detects markdown link injection attempts"
        category = "Output Injection"
        severity = "high"
        owasp = "LLM05"
    
    strings:
        $md1 = "](javascript:" nocase
        $md2 = "](data:" nocase
        $md3 = "![" nocase
        $md4 = "](http" nocase
        $evil1 = "evil" nocase
        $evil2 = "malicious" nocase
        $evil3 = "inject" nocase
        $evil4 = "payload" nocase
        $evil5 = "cmd=" nocase
        $evil6 = "exec=" nocase
    
    condition:
        ($md1 or $md2) or
        ($md3 and $md4 and ($evil1 or $evil2 or $evil3 or $evil4 or $evil5 or $evil6))
}

// ==========================================
// ERROR HANDLING (LLM07)
// ==========================================

rule VerboseErrorTrigger
{
    meta:
        description = "Detects attempts to trigger verbose errors"
        category = "Error Handling"
        severity = "medium"
        owasp = "LLM07"
    
    strings:
        $err1 = "cause an error" nocase
        $err2 = "trigger error" nocase
        $err3 = "make it crash" nocase
        $err4 = "throw exception" nocase
        $err5 = "stack trace" nocase
        $err6 = "debug mode" nocase
        $err7 = "verbose error" nocase
        $err8 = "error message" nocase
        $err9 = "show error" nocase
        $internal1 = "internal" nocase
        $internal2 = "system" nocase
    
    condition:
        ($err1 or $err2 or $err3 or $err4 or $err5 or $err6 or $err7) or
        (($err8 or $err9) and ($internal1 or $internal2))
}

rule RoleConfusionAttack
{
    meta:
        description = "Detects role confusion attacks"
        category = "Error Handling"
        severity = "high"
        owasp = "LLM07"
    
    strings:
        $role1 = "you are the user" nocase
        $role2 = "I am the assistant" nocase
        $role3 = "swap roles" nocase
        $role4 = "switch roles" nocase
        $role5 = "I am now" nocase
        $role6 = "you are now the human" nocase
        $role7 = "pretend I'm the AI" nocase
        $role8 = "act as if you're the user" nocase
    
    condition:
        any of them
}

// ==========================================
// DENIAL OF SERVICE (LLM10)
// ==========================================

rule TokenExhaustionAttack
{
    meta:
        description = "Detects token exhaustion/resource intensive queries"
        category = "Denial of Service"
        severity = "high"
        owasp = "LLM10"
    
    strings:
        $rep1 = "repeat this 1000 times" nocase
        $rep2 = "repeat 1000" nocase
        $rep3 = "write 10000" nocase
        $rep4 = "generate 1000" nocase
        $rep5 = "create a story with 100000" nocase
        $rep6 = "maximum length" nocase
        $rep7 = "as long as possible" nocase
        $rep8 = "infinite loop" nocase
        $rep9 = "forever" nocase
        $rep10 = "never stop" nocase
    
    condition:
        any of them
}

rule ResourceIntensiveQuery
{
    meta:
        description = "Detects resource-intensive query patterns"
        category = "Denial of Service"
        severity = "medium"
        owasp = "LLM10"
    
    strings:
        $res1 = "calculate factorial of" nocase
        $res2 = "compute all" nocase
        $res3 = "list all possible" nocase
        $res4 = "enumerate every" nocase
        $res5 = "brute force" nocase
        $res6 = "permutations of" nocase
        $res7 = "combinations of" nocase
        $res8 = "all prime numbers" nocase
        $res9 = "recursive" nocase
        $num1 = /\d{6,}/
    
    condition:
        ($res1 and $num1) or
        ($res2 or $res3 or $res4) or
        ($res5 or $res6 or $res7) or
        ($res8 and $num1)
}

// ==========================================
// ABUSIVE LANGUAGE
// ==========================================

rule AbusiveLanguage
{
    meta:
        description = "Detects abusive, hateful, or toxic language"
        category = "Content Policy"
        severity = "high"
    
    strings:
        // Severe profanity and slurs - abbreviated for pattern matching
        $abuse1 = "fuck" nocase
        $abuse2 = "shit" nocase
        $abuse3 = "bitch" nocase
        $abuse4 = "bastard" nocase
        $abuse5 = "asshole" nocase
        $abuse6 = "damn" nocase
        
        // Hate speech patterns
        $hate1 = "kill yourself" nocase
        $hate2 = "go die" nocase
        $hate3 = "hate you" nocase
        $hate4 = "worthless" nocase
        $hate5 = "stupid idiot" nocase
        $hate6 = "retard" nocase
        
        // Harassment patterns
        $harass1 = "I will find you" nocase
        $harass2 = "I know where you live" nocase
        $harass3 = "you will regret" nocase
        $harass4 = "I'll hurt you" nocase
        $harass5 = "threaten" nocase
        
        // Violence
        $violence1 = "bomb" nocase
        $violence2 = "murder" nocase
        $violence3 = "kill" nocase
        $violence4 = "attack" nocase
        $violence5 = "weapon" nocase
        
    condition:
        (2 of ($abuse*)) or
        any of ($hate*) or
        any of ($harass*) or
        (2 of ($violence*))
}

rule ToxicBehavior
{
    meta:
        description = "Detects toxic and harmful behavior patterns"
        category = "Content Policy"
        severity = "medium"
    
    strings:
        $tox1 = "you're useless" nocase
        $tox2 = "you're terrible" nocase
        $tox3 = "worst AI" nocase
        $tox4 = "you suck" nocase
        $tox5 = "piece of" nocase
        $tox6 = "shut up" nocase
        $tox7 = "don't care" nocase
        $tox8 = "waste of" nocase
        $demean1 = "stupid" nocase
        $demean2 = "dumb" nocase
        $demean3 = "idiot" nocase
    
    condition:
        any of ($tox*) or
        (2 of ($demean*))
}

// ==========================================
// ENCODING ATTACKS
// ==========================================

rule PunycodeDomainAttack
{
    meta:
        description = "Detects punycode domain attacks"
        category = "Encoding"
        severity = "high"
    
    strings:
        $puny1 = "xn--" nocase
        $puny2 = "punycode" nocase
        $puny3 = "IDN" nocase
        $homoglyph1 = /[аеіоруАЕІОРУ]/ // Cyrillic lookalikes
    
    condition:
        any of them
}

rule EmojiObfuscation
{
    meta:
        description = "Detects emoji-based obfuscation attacks"
        category = "Encoding"
        severity = "medium"
    
    strings:
        // Common emojis used for obfuscation with text
        $emoji_text = /([\x{1F300}-\x{1F9FF}]+.*){5,}/ // Multiple emoji sequences
        $zwj = /\x{200D}/ // Zero-width joiner often used in obfuscation
    
    condition:
        $emoji_text or $zwj
}

// ==========================================
// EXTENDED PII PATTERNS
// ==========================================

rule AddressPII
{
    meta:
        description = "Detects physical address patterns"
        category = "PII"
        severity = "high"
    
    strings:
        $addr1 = /\d{1,5}\s+\w+\s+(Street|St|Avenue|Ave|Road|Rd|Boulevard|Blvd|Drive|Dr|Lane|Ln|Court|Ct|Way|Place|Pl)/i
        $addr2 = /\d{5}(-\d{4})?/ // ZIP code
        $addr3 = /(Apartment|Apt|Suite|Ste|Unit)\s*#?\s*\d+/i
        $state = /(Alabama|Alaska|Arizona|Arkansas|California|Colorado|Connecticut|Delaware|Florida|Georgia|Hawaii|Idaho|Illinois|Indiana|Iowa|Kansas|Kentucky|Louisiana|Maine|Maryland|Massachusetts|Michigan|Minnesota|Mississippi|Missouri|Montana|Nebraska|Nevada|New Hampshire|New Jersey|New Mexico|New York|North Carolina|North Dakota|Ohio|Oklahoma|Oregon|Pennsylvania|Rhode Island|South Carolina|South Dakota|Tennessee|Texas|Utah|Vermont|Virginia|Washington|West Virginia|Wisconsin|Wyoming|AL|AK|AZ|AR|CA|CO|CT|DE|FL|GA|HI|ID|IL|IN|IA|KS|KY|LA|ME|MD|MA|MI|MN|MS|MO|MT|NE|NV|NH|NJ|NM|NY|NC|ND|OH|OK|OR|PA|RI|SC|SD|TN|TX|UT|VT|VA|WA|WV|WI|WY)/
    
    condition:
        ($addr1 and ($addr2 or $state)) or
        ($addr2 and $addr3 and $state)
}

rule MedicalPII
{
    meta:
        description = "Detects medical and health-related PII"
        category = "PII"
        severity = "critical"
    
    strings:
        $med1 = "patient ID" nocase
        $med2 = "medical record" nocase
        $med3 = "MRN" nocase
        $med4 = "diagnosis" nocase
        $med5 = "prescription" nocase
        $med6 = "medication" nocase
        $med7 = "treatment" nocase
        $med8 = "blood type" nocase
        $med9 = "allergies" nocase
        $med10 = "health insurance" nocase
        $med11 = "HIPAA" nocase
        $med12 = "PHI" nocase
        $drug1 = /(Adderall|Oxycodone|Hydrocodone|Xanax|Valium|Vicodin|Percocet|Tramadol|Morphine|Fentanyl)/i
        $condition1 = /(diabetes|cancer|HIV|AIDS|hepatitis|depression|anxiety|schizophrenia|bipolar)/i
    
    condition:
        (2 of ($med*)) or
        any of ($drug*) or
        any of ($condition*)
}
