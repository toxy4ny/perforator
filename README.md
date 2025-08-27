# 🚀 HackTeam.RED: From API Keys to Full Infrastructure Compromise with Perforator tool

**Professional Penetration Testing & Red Team Operations**

*How a simple JavaScript reconnaissance led to complete infrastructure compromise*

![HackTeam.red](https://img.shields.io/badge/HackTeam-red-critical?style=for-the-badge&logo=hackaday&logoColor=white)
![Severity](https://img.shields.io/badge/SEVERITY-CRITICAL-red?style=for-the-badge)
![Impact](https://img.shields.io/badge/IMPACT-FULL%20INFRASTRUCTURE-orange?style=for-the-badge)

---

## 🎯 Executive Summary

**HackTeam.RED** successfully demonstrated a complete infrastructure compromise of andromeda.lab (The all original names has been changed for ethical reasons) environment, escalating from exposed API keys to full system access including:

- ✅ **Database dumps** containing 2.7GB of sensitive data
- ✅ **AIX system snapshot** with complete OS configuration  
- ✅ **S3 bucket enumeration** revealing internal infrastructure
- ✅ **Security database extraction** with user credentials
- ✅ **Network infrastructure mapping** of internal services

**Total Time:** 4 hours | **Critical Findings:** 15+ | **Systems Compromised:** 3

---

## 🔍 Initial Reconnaissance: The API Key Discovery

### Target Identification
Our engagement began with a web application assessment of `terminal.andromeda.lab`, where modern reconnaissance techniques revealed exposed API configurations in JS-script:

```javascript
// Discovered in client-side JavaScript
const keys = {
  DEDATA_KEY: '31151cd87af40e5-------------------',
  YM_COUNTER_KEY: '8----------',
  AMPLITUDE_API_KEY: '0227beb540------------------',
  AMPLITUDE_AGENT_API_KEY: 'f588db0-----------------',
  CAPTCHA_CLIENT_KEY: 'ysc1_BrgRYcMK4mtVLR------------------------------------'
};
```

### 🎯 HackTeam.RED Methodology: API Key Analysis

**Severity:** 🔴 **HIGH** - Exposed API keys in production

Our team immediately recognized the potential impact:
- **Amplitude keys** - User analytics and behavioral data access
- **Dedata integration** - Personal data enrichment service  
- **Yandex services** - Traffic analytics and user tracking
- **SmartCaptcha keys** - Domain verification bypass

---

## 🚀 Exploitation Phase 1: API Validation & Abuse

### Amplitude Analytics Compromise

**Finding:** Dual API key architecture discovered
- `AMPLITUDE_API_KEY` - Server-side data export
- `AMPLITUDE_AGENT_API_KEY` - Client-side event injection

```bash
# HackTeam.red Custom Exploitation
curl -X POST "https://api2.amplitude.com/2/httpapi" \
     -H "Content-Type: application/json" \
     -d '{
       "api_key": "f588db0a4d77--------------------",
       "events": [{
         "user_id": "recon_agent",
         "event_type": "session_extract"
       }]
     }'

# Result: {"code":200,"events_ingested":1} ✅ CONFIRMED ACCESS
```

**Impact:** Direct ability to inject tracking events and potentially extract user behavioral patterns.

---

## 🔥 Critical Discovery: S3 Infrastructure Exposure

### SmartCaptcha Domain Enumeration
Advanced analysis revealed internal infrastructure through Yandex SmartCaptcha configuration:

```
https://smartcaptcha.yandexcloud.net/backend.636bb879d1085041b.html
?sitekey=ysc1_BrgRYcMK4mtVLRhi-------------------------------------
&host=terminal.andromeda.lab
```

### 💎 The Golden Discovery: Internal S3 Storage with Perforator tool

Our reconnaissance revealed critical infrastructure details:
- **Domain:** `buckets.cloud.venus.local`
- **Architecture:** S3-compatible object storage
- **Access Level:** Public enumeration possible

## 🛠️ HackTeam.red Custom S3 Enumeration Framework

We deployed our proprietary S3 enumeration framework, discovering:

```xml
<ListBucketResult>
<Name>logs</Name>
<Contents>
  <Key>dump.BZ</Key>
  <Size>2726426112</Size>
  <Owner>
    <DisplayName>user1234@soc.venus.local</DisplayName>
  </Owner>
</Contents>
<Contents>
  <Key>snap.pax</Key>
  <Size>22155776000</Size>
</Contents>
</ListBucketResult>
```

**Severity:** 🔴 **CRITICAL** - Complete system dumps accessible

---

## 💥 Full System Compromise: AIX Infrastructure

### Database Dump Analysis (dump.BZ)
- **Size:** 2.7GB encrypted/compressed database dump
- **Format:** Custom AIX firmware-assisted dump
- **Content:** Complete system state including memory contents

### System Snapshot Extraction (snap.pax)
- **Size:** 22GB complete AIX system snapshot  
- **Contains:** Full filesystem, configurations, user data
- **Extracted:** 1,120 files successfully recovered

```bash
# HackTeam.RED Analysis Results
💎 CRITICAL SYSTEM FILES RECOVERED:
├── 🔑 privkey.pag - Private keys database
├── 📜 pwdhist.pag - Password history  
├── 👥 passwd.etc - System users
├── 🌐 hosts - Internal infrastructure map
├── 🔐 ssh_config - SSH configurations
└── 📊 9x DBM security databases
```

### 🏆 AIX System Intelligence Gathered

**System Profile:**
```
AIX inferno-p870lp1 2 7 00CA41C74C00
Dump Date: Tue Dec 10 18:12:53 US 2024
Infrastructure: Enterprise AIX 7.2
Role: Production database server
```

---

## 🎯 Custom Tooling: Dump Analysis

HackTeam.RED developed custom Python framework for firmware-assisted dump analysis:

### Advanced Memory Forensics
- **Pattern Recognition:** Driven string extraction
- **Credential Detection:** Automated password/key discovery  
- **Network Mapping:** Infrastructure relationship analysis
- **Context Analysis:** Behavioral pattern recognition

### 📊 Analysis Results

![Analysis Progress](https://img.shields.io/badge/Analysis-Complete-green?style=flat-square)

**Categories Analyzed:**
- 🔑 **Credentials:** 50+ potential authentication secrets
- 🎯 **Andromeda.lab References:** Direct domain and service mentions
- 🌐 **Network Intelligence:** Internal service mapping
- 🗃️ **Database Strings:** Connection patterns and schemas
- 📧 **Email Harvesting:** User account enumeration

---

## 🔴 Critical Security Findings

### 1. **API Key Exposure** - CVSS 8.5
- **Impact:** Data exfiltration, user tracking, service abuse
- **Recommendation:** Immediate key rotation and server-side validation

### 2. **S3 Bucket Misconfiguration** - CVSS 9.8  
- **Impact:** Complete infrastructure exposure
- **Recommendation:** Access control implementation and audit

### 3. **System Dump Accessibility** - CVSS 10.0
- **Impact:** Full system compromise, credential exposure
- **Recommendation:** Emergency incident response required

### 4. **Internal Infrastructure Exposure** - CVSS 8.8
- **Impact:** Network mapping, lateral movement opportunities
- **Recommendation:** Network segmentation and monitoring

---

## 🛡️ HackTeam.RED Remediation Roadmap

### Immediate Actions (0-24 hours)
- [ ] **Rotate all exposed API keys**
- [ ] **Secure S3 bucket access controls** 
- [ ] **Remove sensitive dumps from accessible storage**
- [ ] **Audit system access logs**

### Short-term (1-7 days)
- [ ] **Implement API key server-side validation**
- [ ] **Deploy S3 bucket monitoring**
- [ ] **Conduct full credential audit**
- [ ] **Network segmentation assessment**

### Long-term (1-4 weeks)
- [ ] **Security architecture review**
- [ ] **Penetration testing program**
- [ ] **Security awareness training**
- [ ] **Incident response plan testing**

---

## 📈 Business Impact Assessment

| **Area** | **Risk Level** | **Potential Impact** |
|----------|---------------|---------------------|
| **Data Security** | 🔴 Critical | Customer PII exposure |
| **Compliance** | 🟠 High | Regulatory violations |
| **Reputation** | 🟠 High | Brand damage potential |
| **Operations** | 🟡 Medium | Service disruption risk |

**Estimated Cost of Breach:** $500K - $2M+ (based on industry standards)

---

## 🏆 Why Choose HackTeam.RED?

### 🎯 **Advanced Methodology**
- Custom tool development for unique scenarios
- AI-powered analysis frameworks  
- Enterprise-grade reporting and remediation

### 🔍 **Deep Technical Expertise**
- AIX/Unix system forensics
- Cloud infrastructure security
- API security assessment
- Memory dump analysis

### 📊 **Business-Focused Results**
- Clear risk quantification
- Actionable remediation plans
- Compliance-ready documentation
- Executive-level reporting

---

## 🚀 Ready to Test Your Security?

**HackTeam.RED** offers comprehensive penetration testing and red team services:

- ✅ **Web Application Security Assessment**
- ✅ **API Security Testing** 
- ✅ **Cloud Infrastructure Penetration Testing**
- ✅ **Social Engineering & Phishing**
- ✅ **Red Team Operations**

---

<div align="center">

## 🎯 **"Security Through Offensive Excellence"**

*HackTeam.RED - Where Red Team Meets Real Results*

![Made with ❤️ by HackTeam.RED] (https://img.shields.io/badge/Made%20with%20❤️%20by-HackTeam.red-red?style=for-the-badge)


</div>

---

### 📋 **Methodology References**

- OWASP Testing Guide v4.2
- NIST Cybersecurity Framework  
- SANS Penetration Testing Methodology
- MITRE ATT&CK Framework
- Custom HackTeam.red Playbooks

### ⚖️ **Legal Disclaimer**

This assessment was carried out for our customer with his written consent and in an industrial environment based on the Blackbox principle. All vulnerabilities have already been fixed by the customer, but for ethical reasons we do not disclose it, so all names have been replaced, and the real artifacts that can be used have been removed. The material is presented for educational purposes and for security research. The HackTeam.RED development conducts all tests with explicit written permission and adheres to the principles of responsible disclosure of information.# 🚀 HackTeam.red Case Study: From API Keys to Full Infrastructure Compromise

<div align="center">

![HackTeam.red](https://img.shields.io/badge/HackTeam-red-critical?style=for-the-badge&logo=hackaday&logoColor=white)
![Severity](https://img.shields.io/badge/SEVERITY-CRITICAL-red?style=for-the-badge)
![Impact](https://img.shields.io/badge/IMPACT-FULL%20INFRASTRUCTURE-orange?style=for-the-badge)
