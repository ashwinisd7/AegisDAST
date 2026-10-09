# DAST Security Assessment Report

**Target URL:** `http://demo.testfire.net/`  
**Scan Timestamp:** 2026-10-09 08:31:27 UTC  
**Audit Duration:** 930.99s  
**Total Crawled Endpoints:** 10  
**Total Findings:** 81 (Confirmed: 81, False Positives: 0)  

---

## Executive Summary

| Metric / Severity | Count |
| :--- | :---: |
| **Confirmed Findings (AI)** | **81** |
| **False Positives (AI)** | **0** |
| **CRITICAL** | 0 |
| **HIGH** | 18 |
| **MEDIUM** | 33 |
| **LOW** | 30 |
| **INFO** | 0 |
| **TOTAL** | **81** |

---

## Confirmed Vulnerability Findings (81)

### 1. [MEDIUM] Missing Security Header: Content-Security-Policy

* **Detector Plugin:** `security_headers`
* **Evidence Type:** `http_traffic`
* **Affected URL:** `GET http://demo.testfire.net/search.jsp`

#### Description
Protects against Cross-Site Scripting (XSS), data injection, and clickjacking attacks.

#### Technical Evidence
```text
HTTP Traffic Evidence:
Missing Recommended Security Header: Content-Security-Policy
Status Code: 200
Observed Headers: content-length, content-type, date, server
```

#### HTTP Request Evidence
```http
GET http://demo.testfire.net/search.jsp
host: demo.testfire.net
accept-encoding: gzip, deflate
connection: keep-alive
user-agent: DAST-Security-Auditor/1.0 (+authorized-security-assessment)
accept: */*
cookie: JSESSIONID=4F0B4AB10DD4DD22B9B11DA8BDA795BC; AltoroAccounts=ODAwMDAyflNhdmluZ3N+LTguOTk5OTk3NDMyMDM3Nzc1RTI2fDgwMDAwM35DaGVja2luZ345LjAwMDAxNzc1MjQ1MTcwN0UyNnw0NTM5MDgyMDM5Mzk2Mjg4fkNyZWRpdCBDYXJkfi0xLjE4NDQ2NzQ0MDc4MDA1NjVFMjB8ODAwMDExfkNoZWNraW5nfjEuOTk5OTk5ODQ1NzNFMTF8ODAwMDEzfkNoZWNraW5nfjQwMC4wfDgwMDAxNH5TYXZpbmdzfi00NDc1LjB8ODAwMDE1fklSQX41MDAwLjB8ODAwMDE2flNhdmluZ3N+MC4wfDgwMDAxN35TYXZpbmdzfjAuMHw4MDAwMTh+U2F2aW5nc34wLjB8ODAwMDE5flNhdmluZ3N+MC4wfDgwMDAyMH5TYXZpbmdzfjEuMDY2MDIwNjk2Njk3NzQ1OEUyMXw4MDAwMjF+Q2hlY2tpbmd+MTcwLjB8
authorization: Basic anNtaXRoOmRlbW8xMjM0


```

#### HTTP Response Evidence
```http
HTTP/1.1 200 (299.9ms)
server: Apache-Coyote/1.1
content-type: text/html;charset=ISO-8859-1
content-length: 6866
date: Fri, 09 Oct 2026 08:32:07 GMT



 
    

 

<!-- BEGIN HEADER -->
<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">

<html xmlns="http://www.w3.org/1999/xhtml" xml:lang="en" >



<head>
	<title>Altoro Mutual</title>
  <meta http-equiv="Content-Type" content="text/html; charset=iso-8859-1" />
  <link href="/style.css" rel="stylesheet" type="text/css" />
</head>
<body style="margin-top:5px;">

<div id="header" style="margin-bottom:5px; width: 99%;">
  <form
```

#### Remediation
> Define and enforce a strict Content-Security-Policy (CSP) restricting trusted sources.

---

### 2. [MEDIUM] Missing Security Header: X-Frame-Options

* **Detector Plugin:** `security_headers`
* **Evidence Type:** `http_traffic`
* **Affected URL:** `GET http://demo.testfire.net/search.jsp`

#### Description
Defends against UI redress attacks (Clickjacking) by disallowing framing.

#### Technical Evidence
```text
HTTP Traffic Evidence:
Missing Recommended Security Header: X-Frame-Options
Status Code: 200
Observed Headers: content-length, content-type, date, server
```

#### HTTP Request Evidence
```http
GET http://demo.testfire.net/search.jsp
host: demo.testfire.net
accept-encoding: gzip, deflate
connection: keep-alive
user-agent: DAST-Security-Auditor/1.0 (+authorized-security-assessment)
accept: */*
cookie: JSESSIONID=4F0B4AB10DD4DD22B9B11DA8BDA795BC; AltoroAccounts=ODAwMDAyflNhdmluZ3N+LTguOTk5OTk3NDMyMDM3Nzc1RTI2fDgwMDAwM35DaGVja2luZ345LjAwMDAxNzc1MjQ1MTcwN0UyNnw0NTM5MDgyMDM5Mzk2Mjg4fkNyZWRpdCBDYXJkfi0xLjE4NDQ2NzQ0MDc4MDA1NjVFMjB8ODAwMDExfkNoZWNraW5nfjEuOTk5OTk5ODQ1NzNFMTF8ODAwMDEzfkNoZWNraW5nfjQwMC4wfDgwMDAxNH5TYXZpbmdzfi00NDc1LjB8ODAwMDE1fklSQX41MDAwLjB8ODAwMDE2flNhdmluZ3N+MC4wfDgwMDAxN35TYXZpbmdzfjAuMHw4MDAwMTh+U2F2aW5nc34wLjB8ODAwMDE5flNhdmluZ3N+MC4wfDgwMDAyMH5TYXZpbmdzfjEuMDY2MDIwNjk2Njk3NzQ1OEUyMXw4MDAwMjF+Q2hlY2tpbmd+MTcwLjB8
authorization: Basic anNtaXRoOmRlbW8xMjM0


```

#### HTTP Response Evidence
```http
HTTP/1.1 200 (299.9ms)
server: Apache-Coyote/1.1
content-type: text/html;charset=ISO-8859-1
content-length: 6866
date: Fri, 09 Oct 2026 08:32:07 GMT



 
    

 

<!-- BEGIN HEADER -->
<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">

<html xmlns="http://www.w3.org/1999/xhtml" xml:lang="en" >



<head>
	<title>Altoro Mutual</title>
  <meta http-equiv="Content-Type" content="text/html; charset=iso-8859-1" />
  <link href="/style.css" rel="stylesheet" type="text/css" />
</head>
<body style="margin-top:5px;">

<div id="header" style="margin-bottom:5px; width: 99%;">
  <form
```

#### Remediation
> Set X-Frame-Options to DENY or SAMEORIGIN.

---

### 3. [LOW] Missing Security Header: X-Content-Type-Options

* **Detector Plugin:** `security_headers`
* **Evidence Type:** `http_traffic`
* **Affected URL:** `GET http://demo.testfire.net/search.jsp`

#### Description
Prevents MIME-type sniffing which can lead to script execution via non-executable files.

#### Technical Evidence
```text
HTTP Traffic Evidence:
Missing Recommended Security Header: X-Content-Type-Options
Status Code: 200
Observed Headers: content-length, content-type, date, server
```

#### HTTP Request Evidence
```http
GET http://demo.testfire.net/search.jsp
host: demo.testfire.net
accept-encoding: gzip, deflate
connection: keep-alive
user-agent: DAST-Security-Auditor/1.0 (+authorized-security-assessment)
accept: */*
cookie: JSESSIONID=4F0B4AB10DD4DD22B9B11DA8BDA795BC; AltoroAccounts=ODAwMDAyflNhdmluZ3N+LTguOTk5OTk3NDMyMDM3Nzc1RTI2fDgwMDAwM35DaGVja2luZ345LjAwMDAxNzc1MjQ1MTcwN0UyNnw0NTM5MDgyMDM5Mzk2Mjg4fkNyZWRpdCBDYXJkfi0xLjE4NDQ2NzQ0MDc4MDA1NjVFMjB8ODAwMDExfkNoZWNraW5nfjEuOTk5OTk5ODQ1NzNFMTF8ODAwMDEzfkNoZWNraW5nfjQwMC4wfDgwMDAxNH5TYXZpbmdzfi00NDc1LjB8ODAwMDE1fklSQX41MDAwLjB8ODAwMDE2flNhdmluZ3N+MC4wfDgwMDAxN35TYXZpbmdzfjAuMHw4MDAwMTh+U2F2aW5nc34wLjB8ODAwMDE5flNhdmluZ3N+MC4wfDgwMDAyMH5TYXZpbmdzfjEuMDY2MDIwNjk2Njk3NzQ1OEUyMXw4MDAwMjF+Q2hlY2tpbmd+MTcwLjB8
authorization: Basic anNtaXRoOmRlbW8xMjM0


```

#### HTTP Response Evidence
```http
HTTP/1.1 200 (299.9ms)
server: Apache-Coyote/1.1
content-type: text/html;charset=ISO-8859-1
content-length: 6866
date: Fri, 09 Oct 2026 08:32:07 GMT



 
    

 

<!-- BEGIN HEADER -->
<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">

<html xmlns="http://www.w3.org/1999/xhtml" xml:lang="en" >



<head>
	<title>Altoro Mutual</title>
  <meta http-equiv="Content-Type" content="text/html; charset=iso-8859-1" />
  <link href="/style.css" rel="stylesheet" type="text/css" />
</head>
<body style="margin-top:5px;">

<div id="header" style="margin-bottom:5px; width: 99%;">
  <form
```

#### Remediation
> Set X-Content-Type-Options to 'nosniff'.

---

### 4. [LOW] Missing Security Header: Referrer-Policy

* **Detector Plugin:** `security_headers`
* **Evidence Type:** `http_traffic`
* **Affected URL:** `GET http://demo.testfire.net/search.jsp`

#### Description
Protects sensitive URLs and query parameters from leaking via the HTTP Referer header.

#### Technical Evidence
```text
HTTP Traffic Evidence:
Missing Recommended Security Header: Referrer-Policy
Status Code: 200
Observed Headers: content-length, content-type, date, server
```

#### HTTP Request Evidence
```http
GET http://demo.testfire.net/search.jsp
host: demo.testfire.net
accept-encoding: gzip, deflate
connection: keep-alive
user-agent: DAST-Security-Auditor/1.0 (+authorized-security-assessment)
accept: */*
cookie: JSESSIONID=4F0B4AB10DD4DD22B9B11DA8BDA795BC; AltoroAccounts=ODAwMDAyflNhdmluZ3N+LTguOTk5OTk3NDMyMDM3Nzc1RTI2fDgwMDAwM35DaGVja2luZ345LjAwMDAxNzc1MjQ1MTcwN0UyNnw0NTM5MDgyMDM5Mzk2Mjg4fkNyZWRpdCBDYXJkfi0xLjE4NDQ2NzQ0MDc4MDA1NjVFMjB8ODAwMDExfkNoZWNraW5nfjEuOTk5OTk5ODQ1NzNFMTF8ODAwMDEzfkNoZWNraW5nfjQwMC4wfDgwMDAxNH5TYXZpbmdzfi00NDc1LjB8ODAwMDE1fklSQX41MDAwLjB8ODAwMDE2flNhdmluZ3N+MC4wfDgwMDAxN35TYXZpbmdzfjAuMHw4MDAwMTh+U2F2aW5nc34wLjB8ODAwMDE5flNhdmluZ3N+MC4wfDgwMDAyMH5TYXZpbmdzfjEuMDY2MDIwNjk2Njk3NzQ1OEUyMXw4MDAwMjF+Q2hlY2tpbmd+MTcwLjB8
authorization: Basic anNtaXRoOmRlbW8xMjM0


```

#### HTTP Response Evidence
```http
HTTP/1.1 200 (299.9ms)
server: Apache-Coyote/1.1
content-type: text/html;charset=ISO-8859-1
content-length: 6866
date: Fri, 09 Oct 2026 08:32:07 GMT



 
    

 

<!-- BEGIN HEADER -->
<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">

<html xmlns="http://www.w3.org/1999/xhtml" xml:lang="en" >



<head>
	<title>Altoro Mutual</title>
  <meta http-equiv="Content-Type" content="text/html; charset=iso-8859-1" />
  <link href="/style.css" rel="stylesheet" type="text/css" />
</head>
<body style="margin-top:5px;">

<div id="header" style="margin-bottom:5px; width: 99%;">
  <form
```

#### Remediation
> Configure Referrer-Policy to 'strict-origin-when-cross-origin' or 'no-referrer'.

---

### 5. [LOW] Information Disclosure: Server Header

* **Detector Plugin:** `security_headers`
* **Evidence Type:** `http_traffic`
* **Affected URL:** `GET http://demo.testfire.net/search.jsp`

#### Description
Web server vendor and version banner disclosure: 'Apache-Coyote/1.1' was returned in the server response.

#### Technical Evidence
```text
HTTP Traffic Evidence:
Disclosed Header: Server: Apache-Coyote/1.1
Status Code: 200
```

#### HTTP Request Evidence
```http
GET http://demo.testfire.net/search.jsp
host: demo.testfire.net
accept-encoding: gzip, deflate
connection: keep-alive
user-agent: DAST-Security-Auditor/1.0 (+authorized-security-assessment)
accept: */*
cookie: JSESSIONID=4F0B4AB10DD4DD22B9B11DA8BDA795BC; AltoroAccounts=ODAwMDAyflNhdmluZ3N+LTguOTk5OTk3NDMyMDM3Nzc1RTI2fDgwMDAwM35DaGVja2luZ345LjAwMDAxNzc1MjQ1MTcwN0UyNnw0NTM5MDgyMDM5Mzk2Mjg4fkNyZWRpdCBDYXJkfi0xLjE4NDQ2NzQ0MDc4MDA1NjVFMjB8ODAwMDExfkNoZWNraW5nfjEuOTk5OTk5ODQ1NzNFMTF8ODAwMDEzfkNoZWNraW5nfjQwMC4wfDgwMDAxNH5TYXZpbmdzfi00NDc1LjB8ODAwMDE1fklSQX41MDAwLjB8ODAwMDE2flNhdmluZ3N+MC4wfDgwMDAxN35TYXZpbmdzfjAuMHw4MDAwMTh+U2F2aW5nc34wLjB8ODAwMDE5flNhdmluZ3N+MC4wfDgwMDAyMH5TYXZpbmdzfjEuMDY2MDIwNjk2Njk3NzQ1OEUyMXw4MDAwMjF+Q2hlY2tpbmd+MTcwLjB8
authorization: Basic anNtaXRoOmRlbW8xMjM0


```

#### HTTP Response Evidence
```http
HTTP/1.1 200 (299.9ms)
server: Apache-Coyote/1.1
content-type: text/html;charset=ISO-8859-1
content-length: 6866
date: Fri, 09 Oct 2026 08:32:07 GMT



 
    

 

<!-- BEGIN HEADER -->
<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">

<html xmlns="http://www.w3.org/1999/xhtml" xml:lang="en" >



<head>
	<title>Altoro Mutual</title>
  <meta http-equiv="Content-Type" content="text/html; charset=iso-8859-1" />
  <link href="/style.css" rel="stylesheet" type="text/css" />
</head>
<body style="margin-top:5px;">

<div id="header" style="margin-bottom:5px; width: 99%;">
  <form
```

#### Remediation
> Configure the web server or reverse proxy to strip or suppress the Server header.

---

### 6. [MEDIUM] Missing Clickjacking Defensive Framing Protections

* **Detector Plugin:** `clickjacking`
* **Evidence Type:** `http_traffic`
* **Affected URL:** `GET http://demo.testfire.net/search.jsp`

#### Description
The page lacks both the X-Frame-Options header and CSP frame-ancestors directive. An attacker can frame this target within a transparent <iframe> on a malicious domain to trick authenticated users into clicking sensitive UI buttons (Clickjacking).

#### Technical Evidence
```text
HTTP Response Header Evidence:
X-Frame-Options Header: Missing
CSP frame-ancestors Directive: Missing
```

#### HTTP Request Evidence
```http
GET http://demo.testfire.net/search.jsp
host: demo.testfire.net
accept-encoding: gzip, deflate
connection: keep-alive
user-agent: DAST-Security-Auditor/1.0 (+authorized-security-assessment)
accept: */*
cookie: JSESSIONID=4F0B4AB10DD4DD22B9B11DA8BDA795BC; AltoroAccounts=ODAwMDAyflNhdmluZ3N+LTguOTk5OTk3NDMyMDM3Nzc1RTI2fDgwMDAwM35DaGVja2luZ345LjAwMDAxNzc1MjQ1MTcwN0UyNnw0NTM5MDgyMDM5Mzk2Mjg4fkNyZWRpdCBDYXJkfi0xLjE4NDQ2NzQ0MDc4MDA1NjVFMjB8ODAwMDExfkNoZWNraW5nfjEuOTk5OTk5ODQ1NzNFMTF8ODAwMDEzfkNoZWNraW5nfjQwMC4wfDgwMDAxNH5TYXZpbmdzfi00NDc1LjB8ODAwMDE1fklSQX41MDAwLjB8ODAwMDE2flNhdmluZ3N+MC4wfDgwMDAxN35TYXZpbmdzfjAuMHw4MDAwMTh+U2F2aW5nc34wLjB8ODAwMDE5flNhdmluZ3N+MC4wfDgwMDAyMH5TYXZpbmdzfjEuMDY2MDIwNjk2Njk3NzQ1OEUyMXw4MDAwMjF+Q2hlY2tpbmd+MTcwLjB8
authorization: Basic anNtaXRoOmRlbW8xMjM0


```

#### HTTP Response Evidence
```http
HTTP/1.1 200 (615.1ms)
server: Apache-Coyote/1.1
content-type: text/html;charset=ISO-8859-1
content-length: 6862
date: Fri, 09 Oct 2026 08:32:03 GMT



 
    

 

<!-- BEGIN HEADER -->
<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">

<html xmlns="http://www.w3.org/1999/xhtml" xml:lang="en" >



<head>
	<title>Altoro Mutual</title>
  <meta http-equiv="Content-Type" content="text/html; charset=iso-8859-1" />
  <link href="/style.css" rel="stylesheet" type="text/css" />
</head>
<body style="margin-top:5px;">

<div id="header" style="margin-bottom:5px; width: 99%;">
  <form
```

#### Remediation
> Set 'X-Frame-Options: SAMEORIGIN' or 'Content-Security-Policy: frame-ancestors 'self''.

---

### 7. [MEDIUM] HTML Injection in Parameter 'query'

* **Detector Plugin:** `html_injection`
* **Evidence Type:** `dom_evidence`
* **Affected URL:** `GET http://demo.testfire.net/search.jsp` `[query]`

#### Description
Parameter 'query' reflects user-supplied HTML tags directly into the web page without proper HTML entity encoding, allowing attackers to modify visual layout, deface pages, or perform phishing.

#### Technical Evidence
```text
DOM / HTML Traffic Evidence:
Injected HTML Payload: <h1>HTML_INJ_TEST</h1>
Unencoded Reflection: Matched rendered markup '<h1>HTML_INJ_TEST</h1>'
Technique: Heading tag injection
```

#### HTTP Request Evidence
```http
GET http://demo.testfire.net/search.jsp?query=%3Ch1%3EHTML_INJ_TEST%3C%2Fh1%3E
host: demo.testfire.net
accept-encoding: gzip, deflate
connection: keep-alive
user-agent: DAST-Security-Auditor/1.0 (+authorized-security-assessment)
accept: */*
cookie: JSESSIONID=4F0B4AB10DD4DD22B9B11DA8BDA795BC; AltoroAccounts=ODAwMDAyflNhdmluZ3N+LTguOTk5OTk3NDMyMDM3Nzc1RTI2fDgwMDAwM35DaGVja2luZ345LjAwMDAxNzc1MjQ1MTcwN0UyNnw0NTM5MDgyMDM5Mzk2Mjg4fkNyZWRpdCBDYXJkfi0xLjE4NDQ2NzQ0MDc4MDA1NjVFMjB8ODAwMDExfkNoZWNraW5nfjEuOTk5OTk5ODQ1NzNFMTF8ODAwMDEzfkNoZWNraW5nfjQwMC4wfDgwMDAxNH5TYXZpbmdzfi00NDc1LjB8ODAwMDE1fklSQX41MDAwLjB8ODAwMDE2flNhdmluZ3N+MC4wfDgwMDAxN35TYXZpbmdzfjAuMHw4MDAwMTh+U2F2aW5nc34wLjB8ODAwMDE5flNhdmluZ3N+MC4wfDgwMDAyMH5TYXZpbmdzfjEuMDY2MDIwNjk2Njk3NzQ1OEUyMXw4MDAwMjF+Q2hlY2tpbmd+MTcwLjB8
authorization: Basic anNtaXRoOmRlbW8xMjM0


```

#### HTTP Response Evidence
```http
HTTP/1.1 200 (285.7ms)
server: Apache-Coyote/1.1
content-type: text/html;charset=ISO-8859-1
content-length: 6884
date: Fri, 09 Oct 2026 08:32:04 GMT



 
    

 

<!-- BEGIN HEADER -->
<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">

<html xmlns="http://www.w3.org/1999/xhtml" xml:lang="en" >



<head>
	<title>Altoro Mutual</title>
  <meta http-equiv="Content-Type" content="text/html; charset=iso-8859-1" />
  <link href="/style.css" rel="stylesheet" type="text/css" />
</head>
<body style="margin-top:5px;">

<div id="header" style="margin-bottom:5px; width: 99%;">
  <form
```

#### Remediation
> Contextually HTML entity encode all untrusted inputs before rendering them in the document.

---

### 8. [HIGH] DOM-Based Cross-Site Scripting (DOM XSS) in 'query'

* **Detector Plugin:** `dom_xss`
* **Evidence Type:** `screenshot`
* **Affected URL:** `GET http://demo.testfire.net/search.jsp?query=<script>document.body.style.backgroundColor='red';document.body.insertAdjacentHTML('afterbegin','<h1>dastXSS</h1>')</script>` `[query]`

#### Description
Parameter or URL fragment flows into an unsafe client-side DOM sink without sanitization.

#### Technical Evidence
```text
Live DOM XSS confirmed in browser. Injected vector executed in client-side DOM sink.
Target URL: http://demo.testfire.net/search.jsp?query=<script>document.body.style.backgroundColor='red';document.body.insertAdjacentHTML('afterbegin','<h1>dastXSS</h1>')</script>
Payload: <script>document.body.style.backgroundColor='red';document.body.insertAdjacentHTML('afterbegin','<h1>dastXSS</h1>')</script>
```

#### Visual Screenshot Evidence
![Screenshot Evidence](C:\Users\HP\OneDrive\Desktop\SCANNER\evidence\screenshots\dom_xss\step_004_dom_xss_query_evidence_279b72.png)
*File Path: `C:\Users\HP\OneDrive\Desktop\SCANNER\evidence\screenshots\dom_xss\step_004_dom_xss_query_evidence_279b72.png`*

#### Remediation
> Avoid passing untrusted URL parameters or location hashes to innerHTML/document.write. Use textContent or DOMPurify.

---

### 9. [HIGH] Stored Cross-Site Scripting (XSS) in Form Field 'query'

* **Detector Plugin:** `stored_xss`
* **Evidence Type:** `screenshot`
* **Affected URL:** `GET http://demo.testfire.net/search.jsp` `[query]`

#### Description
Form field 'query' stores arbitrary HTML/JS markup and renders it unencoded.

#### Technical Evidence
```text
Stored XSS confirmed. Injected payload '<script>document.body.style.backgroundColor='red';document.body.insertAdjacentHTML('afterbegin','<h1>dastXSS</h1>')</script>' persisted in backend and rendered without encoding in subsequent page retrieval.
```

#### Visual Screenshot Evidence
![Screenshot Evidence](C:\Users\HP\OneDrive\Desktop\SCANNER\evidence\screenshots\stored_xss\step_005_stored_xss_query_evidence_68a208.png)
*File Path: `C:\Users\HP\OneDrive\Desktop\SCANNER\evidence\screenshots\stored_xss\step_005_stored_xss_query_evidence_68a208.png`*

#### Remediation
> Contextually encode all user-supplied output (HTML entity encoding) and sanitize storage inputs.

---

### 10. [MEDIUM] Missing Clickjacking Defensive Framing Protections

* **Detector Plugin:** `clickjacking`
* **Evidence Type:** `http_traffic`
* **Affected URL:** `GET http://demo.testfire.net/`

#### Description
The page lacks both the X-Frame-Options header and CSP frame-ancestors directive. An attacker can frame this target within a transparent <iframe> on a malicious domain to trick authenticated users into clicking sensitive UI buttons (Clickjacking).

#### Technical Evidence
```text
HTTP Response Header Evidence:
X-Frame-Options Header: Missing
CSP frame-ancestors Directive: Missing
```

#### HTTP Request Evidence
```http
GET http://demo.testfire.net/
host: demo.testfire.net
accept-encoding: gzip, deflate
connection: keep-alive
user-agent: DAST-Security-Auditor/1.0 (+authorized-security-assessment)
accept: */*
cookie: JSESSIONID=4F0B4AB10DD4DD22B9B11DA8BDA795BC; AltoroAccounts=ODAwMDAyflNhdmluZ3N+LTguOTk5OTk3NDMyMDM3Nzc1RTI2fDgwMDAwM35DaGVja2luZ345LjAwMDAxNzc1MjQ1MTcwN0UyNnw0NTM5MDgyMDM5Mzk2Mjg4fkNyZWRpdCBDYXJkfi0xLjE4NDQ2NzQ0MDc4MDA1NjVFMjB8ODAwMDExfkNoZWNraW5nfjEuOTk5OTk5ODQ1NzNFMTF8ODAwMDEzfkNoZWNraW5nfjQwMC4wfDgwMDAxNH5TYXZpbmdzfi00NDc1LjB8ODAwMDE1fklSQX41MDAwLjB8ODAwMDE2flNhdmluZ3N+MC4wfDgwMDAxN35TYXZpbmdzfjAuMHw4MDAwMTh+U2F2aW5nc34wLjB8ODAwMDE5flNhdmluZ3N+MC4wfDgwMDAyMH5TYXZpbmdzfjEuMDY2MDIwNjk2Njk3NzQ1OEUyMXw4MDAwMjF+Q2hlY2tpbmd+MTcwLjB8
authorization: Basic anNtaXRoOmRlbW8xMjM0


```

#### HTTP Response Evidence
```http
HTTP/1.1 200 (295.4ms)
server: Apache-Coyote/1.1
content-type: text/html;charset=ISO-8859-1
transfer-encoding: chunked
date: Fri, 09 Oct 2026 08:32:12 GMT







 
    

 

<!-- BEGIN HEADER -->
<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">

<html xmlns="http://www.w3.org/1999/xhtml" xml:lang="en" >



<head>
	<title>Altoro Mutual</title>
  <meta http-equiv="Content-Type" content="text/html; charset=iso-8859-1" />
  <link href="/style.css" rel="stylesheet" type="text/css" />
</head>
<body style="margin-top:5px;">

<div id="header" style="margin-bottom:5px; width: 99%;">
  <
```

#### Remediation
> Set 'X-Frame-Options: SAMEORIGIN' or 'Content-Security-Policy: frame-ancestors 'self''.

---

### 11. [HIGH] Reflected Cross-Site Scripting (XSS) in Form Field 'query'

* **Detector Plugin:** `xss`
* **Evidence Type:** `screenshot`
* **Affected URL:** `GET http://demo.testfire.net/search.jsp` `[query]`

#### Description
Form field 'query' is vulnerable to reflected Cross-Site Scripting (XSS).

#### Technical Evidence
```text
Visual XSS confirmed. Injected payload '<script>document.body.style.backgroundColor='red';document.body.insertAdjacentHTML('afterbegin','<h1>dastXSS</h1>')</script>' executed in DOM with visual indicators.
```

#### Visual Screenshot Evidence
![Screenshot Evidence](C:\Users\HP\OneDrive\Desktop\SCANNER\evidence\screenshots\xss\step_006_xss_query_evidence_e9217e.png)
*File Path: `C:\Users\HP\OneDrive\Desktop\SCANNER\evidence\screenshots\xss\step_006_xss_query_evidence_e9217e.png`*

#### Remediation
> Contextually encode all user-supplied output (e.g. HTML entity encoding) and enforce a strict CSP.

---

### 12. [MEDIUM] Missing Security Header: Content-Security-Policy

* **Detector Plugin:** `security_headers`
* **Evidence Type:** `http_traffic`
* **Affected URL:** `GET http://demo.testfire.net/`

#### Description
Protects against Cross-Site Scripting (XSS), data injection, and clickjacking attacks.

#### Technical Evidence
```text
HTTP Traffic Evidence:
Missing Recommended Security Header: Content-Security-Policy
Status Code: 200
Observed Headers: content-type, date, server, transfer-encoding
```

#### HTTP Request Evidence
```http
GET http://demo.testfire.net/
host: demo.testfire.net
accept-encoding: gzip, deflate
connection: keep-alive
user-agent: DAST-Security-Auditor/1.0 (+authorized-security-assessment)
accept: */*
cookie: JSESSIONID=4F0B4AB10DD4DD22B9B11DA8BDA795BC; AltoroAccounts=ODAwMDAyflNhdmluZ3N+LTguOTk5OTk3NDMyMDM3Nzc1RTI2fDgwMDAwM35DaGVja2luZ345LjAwMDAxNzc1MjQ1MTcwN0UyNnw0NTM5MDgyMDM5Mzk2Mjg4fkNyZWRpdCBDYXJkfi0xLjE4NDQ2NzQ0MDc4MDA1NjVFMjB8ODAwMDExfkNoZWNraW5nfjEuOTk5OTk5ODQ1NzNFMTF8ODAwMDEzfkNoZWNraW5nfjQwMC4wfDgwMDAxNH5TYXZpbmdzfi00NDc1LjB8ODAwMDE1fklSQX41MDAwLjB8ODAwMDE2flNhdmluZ3N+MC4wfDgwMDAxN35TYXZpbmdzfjAuMHw4MDAwMTh+U2F2aW5nc34wLjB8ODAwMDE5flNhdmluZ3N+MC4wfDgwMDAyMH5TYXZpbmdzfjEuMDY2MDIwNjk2Njk3NzQ1OEUyMXw4MDAwMjF+Q2hlY2tpbmd+MTcwLjB8
authorization: Basic anNtaXRoOmRlbW8xMjM0


```

#### HTTP Response Evidence
```http
HTTP/1.1 200 (293.4ms)
server: Apache-Coyote/1.1
content-type: text/html;charset=ISO-8859-1
transfer-encoding: chunked
date: Fri, 09 Oct 2026 08:32:15 GMT







 
    

 

<!-- BEGIN HEADER -->
<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">

<html xmlns="http://www.w3.org/1999/xhtml" xml:lang="en" >



<head>
	<title>Altoro Mutual</title>
  <meta http-equiv="Content-Type" content="text/html; charset=iso-8859-1" />
  <link href="/style.css" rel="stylesheet" type="text/css" />
</head>
<body style="margin-top:5px;">

<div id="header" style="margin-bottom:5px; width: 99%;">
  <
```

#### Remediation
> Define and enforce a strict Content-Security-Policy (CSP) restricting trusted sources.

---

### 13. [MEDIUM] Missing Security Header: X-Frame-Options

* **Detector Plugin:** `security_headers`
* **Evidence Type:** `http_traffic`
* **Affected URL:** `GET http://demo.testfire.net/`

#### Description
Defends against UI redress attacks (Clickjacking) by disallowing framing.

#### Technical Evidence
```text
HTTP Traffic Evidence:
Missing Recommended Security Header: X-Frame-Options
Status Code: 200
Observed Headers: content-type, date, server, transfer-encoding
```

#### HTTP Request Evidence
```http
GET http://demo.testfire.net/
host: demo.testfire.net
accept-encoding: gzip, deflate
connection: keep-alive
user-agent: DAST-Security-Auditor/1.0 (+authorized-security-assessment)
accept: */*
cookie: JSESSIONID=4F0B4AB10DD4DD22B9B11DA8BDA795BC; AltoroAccounts=ODAwMDAyflNhdmluZ3N+LTguOTk5OTk3NDMyMDM3Nzc1RTI2fDgwMDAwM35DaGVja2luZ345LjAwMDAxNzc1MjQ1MTcwN0UyNnw0NTM5MDgyMDM5Mzk2Mjg4fkNyZWRpdCBDYXJkfi0xLjE4NDQ2NzQ0MDc4MDA1NjVFMjB8ODAwMDExfkNoZWNraW5nfjEuOTk5OTk5ODQ1NzNFMTF8ODAwMDEzfkNoZWNraW5nfjQwMC4wfDgwMDAxNH5TYXZpbmdzfi00NDc1LjB8ODAwMDE1fklSQX41MDAwLjB8ODAwMDE2flNhdmluZ3N+MC4wfDgwMDAxN35TYXZpbmdzfjAuMHw4MDAwMTh+U2F2aW5nc34wLjB8ODAwMDE5flNhdmluZ3N+MC4wfDgwMDAyMH5TYXZpbmdzfjEuMDY2MDIwNjk2Njk3NzQ1OEUyMXw4MDAwMjF+Q2hlY2tpbmd+MTcwLjB8
authorization: Basic anNtaXRoOmRlbW8xMjM0


```

#### HTTP Response Evidence
```http
HTTP/1.1 200 (293.4ms)
server: Apache-Coyote/1.1
content-type: text/html;charset=ISO-8859-1
transfer-encoding: chunked
date: Fri, 09 Oct 2026 08:32:15 GMT







 
    

 

<!-- BEGIN HEADER -->
<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">

<html xmlns="http://www.w3.org/1999/xhtml" xml:lang="en" >



<head>
	<title>Altoro Mutual</title>
  <meta http-equiv="Content-Type" content="text/html; charset=iso-8859-1" />
  <link href="/style.css" rel="stylesheet" type="text/css" />
</head>
<body style="margin-top:5px;">

<div id="header" style="margin-bottom:5px; width: 99%;">
  <
```

#### Remediation
> Set X-Frame-Options to DENY or SAMEORIGIN.

---

### 14. [LOW] Missing Security Header: X-Content-Type-Options

* **Detector Plugin:** `security_headers`
* **Evidence Type:** `http_traffic`
* **Affected URL:** `GET http://demo.testfire.net/`

#### Description
Prevents MIME-type sniffing which can lead to script execution via non-executable files.

#### Technical Evidence
```text
HTTP Traffic Evidence:
Missing Recommended Security Header: X-Content-Type-Options
Status Code: 200
Observed Headers: content-type, date, server, transfer-encoding
```

#### HTTP Request Evidence
```http
GET http://demo.testfire.net/
host: demo.testfire.net
accept-encoding: gzip, deflate
connection: keep-alive
user-agent: DAST-Security-Auditor/1.0 (+authorized-security-assessment)
accept: */*
cookie: JSESSIONID=4F0B4AB10DD4DD22B9B11DA8BDA795BC; AltoroAccounts=ODAwMDAyflNhdmluZ3N+LTguOTk5OTk3NDMyMDM3Nzc1RTI2fDgwMDAwM35DaGVja2luZ345LjAwMDAxNzc1MjQ1MTcwN0UyNnw0NTM5MDgyMDM5Mzk2Mjg4fkNyZWRpdCBDYXJkfi0xLjE4NDQ2NzQ0MDc4MDA1NjVFMjB8ODAwMDExfkNoZWNraW5nfjEuOTk5OTk5ODQ1NzNFMTF8ODAwMDEzfkNoZWNraW5nfjQwMC4wfDgwMDAxNH5TYXZpbmdzfi00NDc1LjB8ODAwMDE1fklSQX41MDAwLjB8ODAwMDE2flNhdmluZ3N+MC4wfDgwMDAxN35TYXZpbmdzfjAuMHw4MDAwMTh+U2F2aW5nc34wLjB8ODAwMDE5flNhdmluZ3N+MC4wfDgwMDAyMH5TYXZpbmdzfjEuMDY2MDIwNjk2Njk3NzQ1OEUyMXw4MDAwMjF+Q2hlY2tpbmd+MTcwLjB8
authorization: Basic anNtaXRoOmRlbW8xMjM0


```

#### HTTP Response Evidence
```http
HTTP/1.1 200 (293.4ms)
server: Apache-Coyote/1.1
content-type: text/html;charset=ISO-8859-1
transfer-encoding: chunked
date: Fri, 09 Oct 2026 08:32:15 GMT







 
    

 

<!-- BEGIN HEADER -->
<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">

<html xmlns="http://www.w3.org/1999/xhtml" xml:lang="en" >



<head>
	<title>Altoro Mutual</title>
  <meta http-equiv="Content-Type" content="text/html; charset=iso-8859-1" />
  <link href="/style.css" rel="stylesheet" type="text/css" />
</head>
<body style="margin-top:5px;">

<div id="header" style="margin-bottom:5px; width: 99%;">
  <
```

#### Remediation
> Set X-Content-Type-Options to 'nosniff'.

---

### 15. [LOW] Missing Security Header: Referrer-Policy

* **Detector Plugin:** `security_headers`
* **Evidence Type:** `http_traffic`
* **Affected URL:** `GET http://demo.testfire.net/`

#### Description
Protects sensitive URLs and query parameters from leaking via the HTTP Referer header.

#### Technical Evidence
```text
HTTP Traffic Evidence:
Missing Recommended Security Header: Referrer-Policy
Status Code: 200
Observed Headers: content-type, date, server, transfer-encoding
```

#### HTTP Request Evidence
```http
GET http://demo.testfire.net/
host: demo.testfire.net
accept-encoding: gzip, deflate
connection: keep-alive
user-agent: DAST-Security-Auditor/1.0 (+authorized-security-assessment)
accept: */*
cookie: JSESSIONID=4F0B4AB10DD4DD22B9B11DA8BDA795BC; AltoroAccounts=ODAwMDAyflNhdmluZ3N+LTguOTk5OTk3NDMyMDM3Nzc1RTI2fDgwMDAwM35DaGVja2luZ345LjAwMDAxNzc1MjQ1MTcwN0UyNnw0NTM5MDgyMDM5Mzk2Mjg4fkNyZWRpdCBDYXJkfi0xLjE4NDQ2NzQ0MDc4MDA1NjVFMjB8ODAwMDExfkNoZWNraW5nfjEuOTk5OTk5ODQ1NzNFMTF8ODAwMDEzfkNoZWNraW5nfjQwMC4wfDgwMDAxNH5TYXZpbmdzfi00NDc1LjB8ODAwMDE1fklSQX41MDAwLjB8ODAwMDE2flNhdmluZ3N+MC4wfDgwMDAxN35TYXZpbmdzfjAuMHw4MDAwMTh+U2F2aW5nc34wLjB8ODAwMDE5flNhdmluZ3N+MC4wfDgwMDAyMH5TYXZpbmdzfjEuMDY2MDIwNjk2Njk3NzQ1OEUyMXw4MDAwMjF+Q2hlY2tpbmd+MTcwLjB8
authorization: Basic anNtaXRoOmRlbW8xMjM0


```

#### HTTP Response Evidence
```http
HTTP/1.1 200 (293.4ms)
server: Apache-Coyote/1.1
content-type: text/html;charset=ISO-8859-1
transfer-encoding: chunked
date: Fri, 09 Oct 2026 08:32:15 GMT







 
    

 

<!-- BEGIN HEADER -->
<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">

<html xmlns="http://www.w3.org/1999/xhtml" xml:lang="en" >



<head>
	<title>Altoro Mutual</title>
  <meta http-equiv="Content-Type" content="text/html; charset=iso-8859-1" />
  <link href="/style.css" rel="stylesheet" type="text/css" />
</head>
<body style="margin-top:5px;">

<div id="header" style="margin-bottom:5px; width: 99%;">
  <
```

#### Remediation
> Configure Referrer-Policy to 'strict-origin-when-cross-origin' or 'no-referrer'.

---

### 16. [LOW] Information Disclosure: Server Header

* **Detector Plugin:** `security_headers`
* **Evidence Type:** `http_traffic`
* **Affected URL:** `GET http://demo.testfire.net/`

#### Description
Web server vendor and version banner disclosure: 'Apache-Coyote/1.1' was returned in the server response.

#### Technical Evidence
```text
HTTP Traffic Evidence:
Disclosed Header: Server: Apache-Coyote/1.1
Status Code: 200
```

#### HTTP Request Evidence
```http
GET http://demo.testfire.net/
host: demo.testfire.net
accept-encoding: gzip, deflate
connection: keep-alive
user-agent: DAST-Security-Auditor/1.0 (+authorized-security-assessment)
accept: */*
cookie: JSESSIONID=4F0B4AB10DD4DD22B9B11DA8BDA795BC; AltoroAccounts=ODAwMDAyflNhdmluZ3N+LTguOTk5OTk3NDMyMDM3Nzc1RTI2fDgwMDAwM35DaGVja2luZ345LjAwMDAxNzc1MjQ1MTcwN0UyNnw0NTM5MDgyMDM5Mzk2Mjg4fkNyZWRpdCBDYXJkfi0xLjE4NDQ2NzQ0MDc4MDA1NjVFMjB8ODAwMDExfkNoZWNraW5nfjEuOTk5OTk5ODQ1NzNFMTF8ODAwMDEzfkNoZWNraW5nfjQwMC4wfDgwMDAxNH5TYXZpbmdzfi00NDc1LjB8ODAwMDE1fklSQX41MDAwLjB8ODAwMDE2flNhdmluZ3N+MC4wfDgwMDAxN35TYXZpbmdzfjAuMHw4MDAwMTh+U2F2aW5nc34wLjB8ODAwMDE5flNhdmluZ3N+MC4wfDgwMDAyMH5TYXZpbmdzfjEuMDY2MDIwNjk2Njk3NzQ1OEUyMXw4MDAwMjF+Q2hlY2tpbmd+MTcwLjB8
authorization: Basic anNtaXRoOmRlbW8xMjM0


```

#### HTTP Response Evidence
```http
HTTP/1.1 200 (293.4ms)
server: Apache-Coyote/1.1
content-type: text/html;charset=ISO-8859-1
transfer-encoding: chunked
date: Fri, 09 Oct 2026 08:32:15 GMT







 
    

 

<!-- BEGIN HEADER -->
<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">

<html xmlns="http://www.w3.org/1999/xhtml" xml:lang="en" >



<head>
	<title>Altoro Mutual</title>
  <meta http-equiv="Content-Type" content="text/html; charset=iso-8859-1" />
  <link href="/style.css" rel="stylesheet" type="text/css" />
</head>
<body style="margin-top:5px;">

<div id="header" style="margin-bottom:5px; width: 99%;">
  <
```

#### Remediation
> Configure the web server or reverse proxy to strip or suppress the Server header.

---

### 17. [HIGH] Reflected Cross-Site Scripting (XSS) in Form Field 'query'

* **Detector Plugin:** `xss`
* **Evidence Type:** `screenshot`
* **Affected URL:** `GET http://demo.testfire.net/search.jsp` `[query]`

#### Description
Form field 'query' is vulnerable to reflected Cross-Site Scripting (XSS).

#### Technical Evidence
```text
Visual XSS confirmed. Injected payload '<script>document.body.style.backgroundColor='red';document.body.insertAdjacentHTML('afterbegin','<h1>dastXSS</h1>')</script>' executed in DOM with visual indicators.
```

#### Visual Screenshot Evidence
![Screenshot Evidence](C:\Users\HP\OneDrive\Desktop\SCANNER\evidence\screenshots\xss\step_007_xss_query_evidence_51b1a8.png)
*File Path: `C:\Users\HP\OneDrive\Desktop\SCANNER\evidence\screenshots\xss\step_007_xss_query_evidence_51b1a8.png`*

#### Remediation
> Contextually encode all user-supplied output (e.g. HTML entity encoding) and enforce a strict CSP.

---

### 18. [MEDIUM] Missing Clickjacking Defensive Framing Protections

* **Detector Plugin:** `clickjacking`
* **Evidence Type:** `http_traffic`
* **Affected URL:** `GET http://demo.testfire.net/bank/showAccount`

#### Description
The page lacks both the X-Frame-Options header and CSP frame-ancestors directive. An attacker can frame this target within a transparent <iframe> on a malicious domain to trick authenticated users into clicking sensitive UI buttons (Clickjacking).

#### Technical Evidence
```text
HTTP Response Header Evidence:
X-Frame-Options Header: Missing
CSP frame-ancestors Directive: Missing
```

#### HTTP Request Evidence
```http
GET http://demo.testfire.net/bank/main.jsp
host: demo.testfire.net
accept-encoding: gzip, deflate
connection: keep-alive
user-agent: DAST-Security-Auditor/1.0 (+authorized-security-assessment)
accept: */*
authorization: Basic anNtaXRoOmRlbW8xMjM0
cookie: JSESSIONID=4F0B4AB10DD4DD22B9B11DA8BDA795BC; AltoroAccounts=ODAwMDAyflNhdmluZ3N+LTguOTk5OTk3NDMyMDM3Nzc1RTI2fDgwMDAwM35DaGVja2luZ345LjAwMDAxNzc1MjQ1MTcwN0UyNnw0NTM5MDgyMDM5Mzk2Mjg4fkNyZWRpdCBDYXJkfi0xLjE4NDQ2NzQ0MDc4MDA1NjVFMjB8ODAwMDExfkNoZWNraW5nfjEuOTk5OTk5ODQ1MjJFMTF8ODAwMDEzfkNoZWNraW5nfjQwMC4wfDgwMDAxNH5TYXZpbmdzfi00NDc1LjB8ODAwMDE1fklSQX41MDAwLjB8ODAwMDE2flNhdmluZ3N+MC4wfDgwMDAxN35TYXZpbmdzfjAuMHw4MDAwMTh+U2F2aW5nc34wLjB8ODAwMDE5flNhdmluZ3N+MC4wfDgwMDAyMH5TYXZpbmdzfjEuMDY2MDIwNjk2Njk3NzQ1OEUyMXw4MDAwMjF+Q2hlY2tpbmd+MTcwLjB8


```

#### HTTP Response Evidence
```http
HTTP/1.1 200 (10854.4ms)
server: Apache-Coyote/1.1
content-type: text/html;charset=ISO-8859-1
content-length: 6489
date: Fri, 09 Oct 2026 08:32:40 GMT



 
    

 

<!-- BEGIN HEADER -->
<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">

<html xmlns="http://www.w3.org/1999/xhtml" xml:lang="en" >



<head>
	<title>Altoro Mutual</title>
  <meta http-equiv="Content-Type" content="text/html; charset=iso-8859-1" />
  <link href="/style.css" rel="stylesheet" type="text/css" />
</head>
<body style="margin-top:5px;">

<div id="header" style="margin-bottom:5px; width: 99%;">
  <form
```

#### Remediation
> Set 'X-Frame-Options: SAMEORIGIN' or 'Content-Security-Policy: frame-ancestors 'self''.

---

### 19. [HIGH] Cross-Site Request Forgery (CSRF) via Sensitive GET Form

* **Detector Plugin:** `csrf`
* **Evidence Type:** `screenshot`
* **Affected URL:** `GET http://demo.testfire.net/bank/showAccount`

#### Description
The form uses HTTP GET to perform sensitive state-changing operations without including a synchronized anti-CSRF token. Using HTTP GET for sensitive state modification allows trivial one-click/zero-click exploitation via hyperlinks, <img>, or <iframe> tags without user awareness.

#### Technical Evidence
```text
DOM Form Evidence:
Form Method: GET
Form Action: showAccount
Input Fields: listAccounts
Form HTML Snippet:
<form action="showAccount" method="get" name="details">
<table border="0">
<tr valign="top">
<td>View Account Details:</td>
<td align="left">
<select id="listAccounts" name="listAccounts" size="1">
<option value="800002">800002 Savings</option>
<option value="800003">800003 Checking</option>
<option value="4539082039396288">4539082039396288 Credit ...
Observed: No hidden anti-CSRF token input field detected inside form.
```

#### Visual Screenshot Evidence
![Screenshot Evidence](C:\Users\HP\OneDrive\Desktop\SCANNER\evidence\screenshots\csrf\step_008_csrf_form_evidence_35e6cc.png)
*File Path: `C:\Users\HP\OneDrive\Desktop\SCANNER\evidence\screenshots\csrf\step_008_csrf_form_evidence_35e6cc.png`*

#### HTTP Request Evidence
```http
GET http://demo.testfire.net/bank/main.jsp
host: demo.testfire.net
accept-encoding: gzip, deflate
connection: keep-alive
user-agent: DAST-Security-Auditor/1.0 (+authorized-security-assessment)
accept: */*
authorization: Basic anNtaXRoOmRlbW8xMjM0
cookie: JSESSIONID=4F0B4AB10DD4DD22B9B11DA8BDA795BC; AltoroAccounts=ODAwMDAyflNhdmluZ3N+LTguOTk5OTk3NDMyMDM3Nzc1RTI2fDgwMDAwM35DaGVja2luZ345LjAwMDAxNzc1MjQ1MTcwN0UyNnw0NTM5MDgyMDM5Mzk2Mjg4fkNyZWRpdCBDYXJkfi0xLjE4NDQ2NzQ0MDc4MDA1NjVFMjB8ODAwMDExfkNoZWNraW5nfjEuOTk5OTk5ODQ1MjJFMTF8ODAwMDEzfkNoZWNraW5nfjQwMC4wfDgwMDAxNH5TYXZpbmdzfi00NDc1LjB8ODAwMDE1fklSQX41MDAwLjB8ODAwMDE2flNhdmluZ3N+MC4wfDgwMDAxN35TYXZpbmdzfjAuMHw4MDAwMTh+U2F2aW5nc34wLjB8ODAwMDE5flNhdmluZ3N+MC4wfDgwMDAyMH5TYXZpbmdzfjEuMDY2MDIwNjk2Njk3NzQ1OEUyMXw4MDAwMjF+Q2hlY2tpbmd+MTcwLjB8


```

#### HTTP Response Evidence
```http
HTTP/1.1 200 (589.7ms)
server: Apache-Coyote/1.1
content-type: text/html;charset=ISO-8859-1
content-length: 6489
date: Fri, 09 Oct 2026 08:32:42 GMT



 
    

 

<!-- BEGIN HEADER -->
<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">

<html xmlns="http://www.w3.org/1999/xhtml" xml:lang="en" >



<head>
	<title>Altoro Mutual</title>
  <meta http-equiv="Content-Type" content="text/html; charset=iso-8859-1" />
  <link href="/style.css" rel="stylesheet" type="text/css" />
</head>
<body style="margin-top:5px;">

<div id="header" style="margin-bottom:5px; width: 99%;">
  <form
```

#### Remediation
> 1. Convert sensitive state-changing actions from HTTP GET to HTTP POST.
2. Include cryptographically random, unpredictable anti-CSRF tokens in all state-changing HTML forms.
3. Enforce 'SameSite=Lax' or 'SameSite=Strict' on session cookies.
4. Require re-authentication (current password) for critical account actions (e.g., password change, email change).

---

### 20. [MEDIUM] Missing Security Header: Content-Security-Policy

* **Detector Plugin:** `security_headers`
* **Evidence Type:** `http_traffic`
* **Affected URL:** `GET http://demo.testfire.net/bank/showAccount`

#### Description
Protects against Cross-Site Scripting (XSS), data injection, and clickjacking attacks.

#### Technical Evidence
```text
HTTP Traffic Evidence:
Missing Recommended Security Header: Content-Security-Policy
Status Code: 200
Observed Headers: content-length, content-type, date, server
```

#### HTTP Request Evidence
```http
GET http://demo.testfire.net/bank/main.jsp
host: demo.testfire.net
accept-encoding: gzip, deflate
connection: keep-alive
user-agent: DAST-Security-Auditor/1.0 (+authorized-security-assessment)
accept: */*
authorization: Basic anNtaXRoOmRlbW8xMjM0
cookie: JSESSIONID=4F0B4AB10DD4DD22B9B11DA8BDA795BC; AltoroAccounts=ODAwMDAyflNhdmluZ3N+LTguOTk5OTk3NDMyMDM3Nzc1RTI2fDgwMDAwM35DaGVja2luZ345LjAwMDAxNzc1MjQ1MTcwN0UyNnw0NTM5MDgyMDM5Mzk2Mjg4fkNyZWRpdCBDYXJkfi0xLjE4NDQ2NzQ0MDc4MDA1NjVFMjB8ODAwMDExfkNoZWNraW5nfjEuOTk5OTk5ODQ0ODJFMTF8ODAwMDEzfkNoZWNraW5nfjQwMC4wfDgwMDAxNH5TYXZpbmdzfi00NDc1LjB8ODAwMDE1fklSQX41MDAwLjB8ODAwMDE2flNhdmluZ3N+MC4wfDgwMDAxN35TYXZpbmdzfjAuMHw4MDAwMTh+U2F2aW5nc34wLjB8ODAwMDE5flNhdmluZ3N+MC4wfDgwMDAyMH5TYXZpbmdzfjEuMDY2MDIwNjk2Njk3NzQ1OEUyMXw4MDAwMjF+Q2hlY2tpbmd+MTcwLjB8


```

#### HTTP Response Evidence
```http
HTTP/1.1 200 (854.8ms)
server: Apache-Coyote/1.1
content-type: text/html;charset=ISO-8859-1
content-length: 6489
date: Fri, 09 Oct 2026 08:33:03 GMT



 
    

 

<!-- BEGIN HEADER -->
<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">

<html xmlns="http://www.w3.org/1999/xhtml" xml:lang="en" >



<head>
	<title>Altoro Mutual</title>
  <meta http-equiv="Content-Type" content="text/html; charset=iso-8859-1" />
  <link href="/style.css" rel="stylesheet" type="text/css" />
</head>
<body style="margin-top:5px;">

<div id="header" style="margin-bottom:5px; width: 99%;">
  <form
```

#### Remediation
> Define and enforce a strict Content-Security-Policy (CSP) restricting trusted sources.

---

### 21. [MEDIUM] Missing Security Header: X-Frame-Options

* **Detector Plugin:** `security_headers`
* **Evidence Type:** `http_traffic`
* **Affected URL:** `GET http://demo.testfire.net/bank/showAccount`

#### Description
Defends against UI redress attacks (Clickjacking) by disallowing framing.

#### Technical Evidence
```text
HTTP Traffic Evidence:
Missing Recommended Security Header: X-Frame-Options
Status Code: 200
Observed Headers: content-length, content-type, date, server
```

#### HTTP Request Evidence
```http
GET http://demo.testfire.net/bank/main.jsp
host: demo.testfire.net
accept-encoding: gzip, deflate
connection: keep-alive
user-agent: DAST-Security-Auditor/1.0 (+authorized-security-assessment)
accept: */*
authorization: Basic anNtaXRoOmRlbW8xMjM0
cookie: JSESSIONID=4F0B4AB10DD4DD22B9B11DA8BDA795BC; AltoroAccounts=ODAwMDAyflNhdmluZ3N+LTguOTk5OTk3NDMyMDM3Nzc1RTI2fDgwMDAwM35DaGVja2luZ345LjAwMDAxNzc1MjQ1MTcwN0UyNnw0NTM5MDgyMDM5Mzk2Mjg4fkNyZWRpdCBDYXJkfi0xLjE4NDQ2NzQ0MDc4MDA1NjVFMjB8ODAwMDExfkNoZWNraW5nfjEuOTk5OTk5ODQ0ODJFMTF8ODAwMDEzfkNoZWNraW5nfjQwMC4wfDgwMDAxNH5TYXZpbmdzfi00NDc1LjB8ODAwMDE1fklSQX41MDAwLjB8ODAwMDE2flNhdmluZ3N+MC4wfDgwMDAxN35TYXZpbmdzfjAuMHw4MDAwMTh+U2F2aW5nc34wLjB8ODAwMDE5flNhdmluZ3N+MC4wfDgwMDAyMH5TYXZpbmdzfjEuMDY2MDIwNjk2Njk3NzQ1OEUyMXw4MDAwMjF+Q2hlY2tpbmd+MTcwLjB8


```

#### HTTP Response Evidence
```http
HTTP/1.1 200 (854.8ms)
server: Apache-Coyote/1.1
content-type: text/html;charset=ISO-8859-1
content-length: 6489
date: Fri, 09 Oct 2026 08:33:03 GMT



 
    

 

<!-- BEGIN HEADER -->
<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">

<html xmlns="http://www.w3.org/1999/xhtml" xml:lang="en" >



<head>
	<title>Altoro Mutual</title>
  <meta http-equiv="Content-Type" content="text/html; charset=iso-8859-1" />
  <link href="/style.css" rel="stylesheet" type="text/css" />
</head>
<body style="margin-top:5px;">

<div id="header" style="margin-bottom:5px; width: 99%;">
  <form
```

#### Remediation
> Set X-Frame-Options to DENY or SAMEORIGIN.

---

### 22. [LOW] Missing Security Header: X-Content-Type-Options

* **Detector Plugin:** `security_headers`
* **Evidence Type:** `http_traffic`
* **Affected URL:** `GET http://demo.testfire.net/bank/showAccount`

#### Description
Prevents MIME-type sniffing which can lead to script execution via non-executable files.

#### Technical Evidence
```text
HTTP Traffic Evidence:
Missing Recommended Security Header: X-Content-Type-Options
Status Code: 200
Observed Headers: content-length, content-type, date, server
```

#### HTTP Request Evidence
```http
GET http://demo.testfire.net/bank/main.jsp
host: demo.testfire.net
accept-encoding: gzip, deflate
connection: keep-alive
user-agent: DAST-Security-Auditor/1.0 (+authorized-security-assessment)
accept: */*
authorization: Basic anNtaXRoOmRlbW8xMjM0
cookie: JSESSIONID=4F0B4AB10DD4DD22B9B11DA8BDA795BC; AltoroAccounts=ODAwMDAyflNhdmluZ3N+LTguOTk5OTk3NDMyMDM3Nzc1RTI2fDgwMDAwM35DaGVja2luZ345LjAwMDAxNzc1MjQ1MTcwN0UyNnw0NTM5MDgyMDM5Mzk2Mjg4fkNyZWRpdCBDYXJkfi0xLjE4NDQ2NzQ0MDc4MDA1NjVFMjB8ODAwMDExfkNoZWNraW5nfjEuOTk5OTk5ODQ0ODJFMTF8ODAwMDEzfkNoZWNraW5nfjQwMC4wfDgwMDAxNH5TYXZpbmdzfi00NDc1LjB8ODAwMDE1fklSQX41MDAwLjB8ODAwMDE2flNhdmluZ3N+MC4wfDgwMDAxN35TYXZpbmdzfjAuMHw4MDAwMTh+U2F2aW5nc34wLjB8ODAwMDE5flNhdmluZ3N+MC4wfDgwMDAyMH5TYXZpbmdzfjEuMDY2MDIwNjk2Njk3NzQ1OEUyMXw4MDAwMjF+Q2hlY2tpbmd+MTcwLjB8


```

#### HTTP Response Evidence
```http
HTTP/1.1 200 (854.8ms)
server: Apache-Coyote/1.1
content-type: text/html;charset=ISO-8859-1
content-length: 6489
date: Fri, 09 Oct 2026 08:33:03 GMT



 
    

 

<!-- BEGIN HEADER -->
<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">

<html xmlns="http://www.w3.org/1999/xhtml" xml:lang="en" >



<head>
	<title>Altoro Mutual</title>
  <meta http-equiv="Content-Type" content="text/html; charset=iso-8859-1" />
  <link href="/style.css" rel="stylesheet" type="text/css" />
</head>
<body style="margin-top:5px;">

<div id="header" style="margin-bottom:5px; width: 99%;">
  <form
```

#### Remediation
> Set X-Content-Type-Options to 'nosniff'.

---

### 23. [LOW] Missing Security Header: Referrer-Policy

* **Detector Plugin:** `security_headers`
* **Evidence Type:** `http_traffic`
* **Affected URL:** `GET http://demo.testfire.net/bank/showAccount`

#### Description
Protects sensitive URLs and query parameters from leaking via the HTTP Referer header.

#### Technical Evidence
```text
HTTP Traffic Evidence:
Missing Recommended Security Header: Referrer-Policy
Status Code: 200
Observed Headers: content-length, content-type, date, server
```

#### HTTP Request Evidence
```http
GET http://demo.testfire.net/bank/main.jsp
host: demo.testfire.net
accept-encoding: gzip, deflate
connection: keep-alive
user-agent: DAST-Security-Auditor/1.0 (+authorized-security-assessment)
accept: */*
authorization: Basic anNtaXRoOmRlbW8xMjM0
cookie: JSESSIONID=4F0B4AB10DD4DD22B9B11DA8BDA795BC; AltoroAccounts=ODAwMDAyflNhdmluZ3N+LTguOTk5OTk3NDMyMDM3Nzc1RTI2fDgwMDAwM35DaGVja2luZ345LjAwMDAxNzc1MjQ1MTcwN0UyNnw0NTM5MDgyMDM5Mzk2Mjg4fkNyZWRpdCBDYXJkfi0xLjE4NDQ2NzQ0MDc4MDA1NjVFMjB8ODAwMDExfkNoZWNraW5nfjEuOTk5OTk5ODQ0ODJFMTF8ODAwMDEzfkNoZWNraW5nfjQwMC4wfDgwMDAxNH5TYXZpbmdzfi00NDc1LjB8ODAwMDE1fklSQX41MDAwLjB8ODAwMDE2flNhdmluZ3N+MC4wfDgwMDAxN35TYXZpbmdzfjAuMHw4MDAwMTh+U2F2aW5nc34wLjB8ODAwMDE5flNhdmluZ3N+MC4wfDgwMDAyMH5TYXZpbmdzfjEuMDY2MDIwNjk2Njk3NzQ1OEUyMXw4MDAwMjF+Q2hlY2tpbmd+MTcwLjB8


```

#### HTTP Response Evidence
```http
HTTP/1.1 200 (854.8ms)
server: Apache-Coyote/1.1
content-type: text/html;charset=ISO-8859-1
content-length: 6489
date: Fri, 09 Oct 2026 08:33:03 GMT



 
    

 

<!-- BEGIN HEADER -->
<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">

<html xmlns="http://www.w3.org/1999/xhtml" xml:lang="en" >



<head>
	<title>Altoro Mutual</title>
  <meta http-equiv="Content-Type" content="text/html; charset=iso-8859-1" />
  <link href="/style.css" rel="stylesheet" type="text/css" />
</head>
<body style="margin-top:5px;">

<div id="header" style="margin-bottom:5px; width: 99%;">
  <form
```

#### Remediation
> Configure Referrer-Policy to 'strict-origin-when-cross-origin' or 'no-referrer'.

---

### 24. [LOW] Information Disclosure: Server Header

* **Detector Plugin:** `security_headers`
* **Evidence Type:** `http_traffic`
* **Affected URL:** `GET http://demo.testfire.net/bank/showAccount`

#### Description
Web server vendor and version banner disclosure: 'Apache-Coyote/1.1' was returned in the server response.

#### Technical Evidence
```text
HTTP Traffic Evidence:
Disclosed Header: Server: Apache-Coyote/1.1
Status Code: 200
```

#### HTTP Request Evidence
```http
GET http://demo.testfire.net/bank/main.jsp
host: demo.testfire.net
accept-encoding: gzip, deflate
connection: keep-alive
user-agent: DAST-Security-Auditor/1.0 (+authorized-security-assessment)
accept: */*
authorization: Basic anNtaXRoOmRlbW8xMjM0
cookie: JSESSIONID=4F0B4AB10DD4DD22B9B11DA8BDA795BC; AltoroAccounts=ODAwMDAyflNhdmluZ3N+LTguOTk5OTk3NDMyMDM3Nzc1RTI2fDgwMDAwM35DaGVja2luZ345LjAwMDAxNzc1MjQ1MTcwN0UyNnw0NTM5MDgyMDM5Mzk2Mjg4fkNyZWRpdCBDYXJkfi0xLjE4NDQ2NzQ0MDc4MDA1NjVFMjB8ODAwMDExfkNoZWNraW5nfjEuOTk5OTk5ODQ0ODJFMTF8ODAwMDEzfkNoZWNraW5nfjQwMC4wfDgwMDAxNH5TYXZpbmdzfi00NDc1LjB8ODAwMDE1fklSQX41MDAwLjB8ODAwMDE2flNhdmluZ3N+MC4wfDgwMDAxN35TYXZpbmdzfjAuMHw4MDAwMTh+U2F2aW5nc34wLjB8ODAwMDE5flNhdmluZ3N+MC4wfDgwMDAyMH5TYXZpbmdzfjEuMDY2MDIwNjk2Njk3NzQ1OEUyMXw4MDAwMjF+Q2hlY2tpbmd+MTcwLjB8


```

#### HTTP Response Evidence
```http
HTTP/1.1 200 (854.8ms)
server: Apache-Coyote/1.1
content-type: text/html;charset=ISO-8859-1
content-length: 6489
date: Fri, 09 Oct 2026 08:33:03 GMT



 
    

 

<!-- BEGIN HEADER -->
<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">

<html xmlns="http://www.w3.org/1999/xhtml" xml:lang="en" >



<head>
	<title>Altoro Mutual</title>
  <meta http-equiv="Content-Type" content="text/html; charset=iso-8859-1" />
  <link href="/style.css" rel="stylesheet" type="text/css" />
</head>
<body style="margin-top:5px;">

<div id="header" style="margin-bottom:5px; width: 99%;">
  <form
```

#### Remediation
> Configure the web server or reverse proxy to strip or suppress the Server header.

---

### 25. [HIGH] Server-Side Includes (SSI) Injection in Parameter 'listAccounts'

* **Detector Plugin:** `ssii`
* **Evidence Type:** `screenshot`
* **Affected URL:** `GET http://demo.testfire.net/bank/showAccount` `[listAccounts]`

#### Description
Parameter 'listAccounts' is vulnerable to SSI Injection. The web server evaluated the injected SSI directive prior to serving the HTML response.

#### Technical Evidence
```text
HTTP Traffic Evidence:
Injected SSI Directive: <!--#exec cmd="echo SSI_CONFIRMED"-->
Evaluated Output: Matched token 'SSI_CONFIRMED'
Technique: SSI Exec command directive
```

#### Visual Screenshot Evidence
![Screenshot Evidence](C:\Users\HP\OneDrive\Desktop\SCANNER\evidence\screenshots\ssii\term_009_ssii_listAccounts_c6db73.png)
*File Path: `C:\Users\HP\OneDrive\Desktop\SCANNER\evidence\screenshots\ssii\term_009_ssii_listAccounts_c6db73.png`*

#### HTTP Request Evidence
```http
GET http://demo.testfire.net/bank/showAccount?listAccounts=%3C%21--%23exec+cmd%3D%22echo+SSI_CONFIRMED%22--%3E
host: demo.testfire.net
accept-encoding: gzip, deflate
connection: keep-alive
user-agent: DAST-Security-Auditor/1.0 (+authorized-security-assessment)
accept: */*
cookie: JSESSIONID=4F0B4AB10DD4DD22B9B11DA8BDA795BC; AltoroAccounts=ODAwMDAyflNhdmluZ3N+LTguOTk5OTk3NDMyMDM3Nzc1RTI2fDgwMDAwM35DaGVja2luZ345LjAwMDAxNzc1MjQ1MTcwN0UyNnw0NTM5MDgyMDM5Mzk2Mjg4fkNyZWRpdCBDYXJkfi0xLjE4NDQ2NzQ0MDc4MDA1NjVFMjB8ODAwMDExfkNoZWNraW5nfjEuOTk5OTk5ODQ0ODJFMTF8ODAwMDEzfkNoZWNraW5nfjQwMC4wfDgwMDAxNH5TYXZpbmdzfi00NDc1LjB8ODAwMDE1fklSQX41MDAwLjB8ODAwMDE2flNhdmluZ3N+MC4wfDgwMDAxN35TYXZpbmdzfjAuMHw4MDAwMTh+U2F2aW5nc34wLjB8ODAwMDE5flNhdmluZ3N+MC4wfDgwMDAyMH5TYXZpbmdzfjEuMDY2MDIwNjk2Njk3NzQ1OEUyMXw4MDAwMjF+Q2hlY2tpbmd+MTcwLjB8
authorization: Basic anNtaXRoOmRlbW8xMjM0


```

#### HTTP Response Evidence
```http
HTTP/1.1 500 (584.0ms)
server: Apache-Coyote/1.1
content-type: text/html;charset=utf-8
content-language: en
content-length: 4193
date: Fri, 09 Oct 2026 08:33:05 GMT
connection: close

<!doctype html><html lang="en"><head><title>HTTP Status 500 – Internal Server Error</title><style type="text/css">H1 {font-family:Tahoma,Arial,sans-serif;color:white;background-color:#525D76;font-size:22px;} H2 {font-family:Tahoma,Arial,sans-serif;color:white;background-color:#525D76;font-size:16px;} H3 {font-family:Tahoma,Arial,sans-serif;color:white;background-color:#525D76;font-size:14px;} BODY {font-family:Tahoma,Arial,sans-serif;color:black;background-color:white;} B {font-family:Tahoma,Ari
```

#### Remediation
> Disable Server-Side Includes (SSI) execution in the web server configuration or sanitize HTML comment syntax.

---

### 26. [MEDIUM] Missing Clickjacking Defensive Framing Protections

* **Detector Plugin:** `clickjacking`
* **Evidence Type:** `http_traffic`
* **Affected URL:** `GET http://demo.testfire.net/bank/main.jsp`

#### Description
The page lacks both the X-Frame-Options header and CSP frame-ancestors directive. An attacker can frame this target within a transparent <iframe> on a malicious domain to trick authenticated users into clicking sensitive UI buttons (Clickjacking).

#### Technical Evidence
```text
HTTP Response Header Evidence:
X-Frame-Options Header: Missing
CSP frame-ancestors Directive: Missing
```

#### HTTP Request Evidence
```http
GET http://demo.testfire.net/bank/main.jsp
host: demo.testfire.net
accept-encoding: gzip, deflate
connection: keep-alive
user-agent: DAST-Security-Auditor/1.0 (+authorized-security-assessment)
accept: */*
cookie: JSESSIONID=4F0B4AB10DD4DD22B9B11DA8BDA795BC; AltoroAccounts=ODAwMDAyflNhdmluZ3N+LTguOTk5OTk3NDMyMDM3Nzc1RTI2fDgwMDAwM35DaGVja2luZ345LjAwMDAxNzc1MjQ1MTcwN0UyNnw0NTM5MDgyMDM5Mzk2Mjg4fkNyZWRpdCBDYXJkfi0xLjE4NDQ2NzQ0MDc4MDA1NjVFMjB8ODAwMDExfkNoZWNraW5nfjEuOTk5OTk5ODQ0ODJFMTF8ODAwMDEzfkNoZWNraW5nfjQwMC4wfDgwMDAxNH5TYXZpbmdzfi00NDc1LjB8ODAwMDE1fklSQX41MDAwLjB8ODAwMDE2flNhdmluZ3N+MC4wfDgwMDAxN35TYXZpbmdzfjAuMHw4MDAwMTh+U2F2aW5nc34wLjB8ODAwMDE5flNhdmluZ3N+MC4wfDgwMDAyMH5TYXZpbmdzfjEuMDY2MDIwNjk2Njk3NzQ1OEUyMXw4MDAwMjF+Q2hlY2tpbmd+MTcwLjB8
authorization: Basic anNtaXRoOmRlbW8xMjM0


```

#### HTTP Response Evidence
```http
HTTP/1.1 200 (567.3ms)
server: Apache-Coyote/1.1
content-type: text/html;charset=ISO-8859-1
content-length: 6489
date: Fri, 09 Oct 2026 08:33:27 GMT



 
    

 

<!-- BEGIN HEADER -->
<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">

<html xmlns="http://www.w3.org/1999/xhtml" xml:lang="en" >



<head>
	<title>Altoro Mutual</title>
  <meta http-equiv="Content-Type" content="text/html; charset=iso-8859-1" />
  <link href="/style.css" rel="stylesheet" type="text/css" />
</head>
<body style="margin-top:5px;">

<div id="header" style="margin-bottom:5px; width: 99%;">
  <form
```

#### Remediation
> Set 'X-Frame-Options: SAMEORIGIN' or 'Content-Security-Policy: frame-ancestors 'self''.

---

### 27. [HIGH] Cross-Site Request Forgery (CSRF) via Sensitive GET Form

* **Detector Plugin:** `csrf`
* **Evidence Type:** `screenshot`
* **Affected URL:** `GET http://demo.testfire.net/bank/main.jsp`

#### Description
The form uses HTTP GET to perform sensitive state-changing operations without including a synchronized anti-CSRF token. Using HTTP GET for sensitive state modification allows trivial one-click/zero-click exploitation via hyperlinks, <img>, or <iframe> tags without user awareness.

#### Technical Evidence
```text
DOM Form Evidence:
Form Method: GET
Form Action: showAccount
Input Fields: listAccounts
Form HTML Snippet:
<form action="showAccount" method="get" name="details">
<table border="0">
<tr valign="top">
<td>View Account Details:</td>
<td align="left">
<select id="listAccounts" name="listAccounts" size="1">
<option value="800002">800002 Savings</option>
<option value="800003">800003 Checking</option>
<option value="4539082039396288">4539082039396288 Credit ...
Observed: No hidden anti-CSRF token input field detected inside form.
```

#### Visual Screenshot Evidence
![Screenshot Evidence](C:\Users\HP\OneDrive\Desktop\SCANNER\evidence\screenshots\csrf\step_010_csrf_form_evidence_1a0ac5.png)
*File Path: `C:\Users\HP\OneDrive\Desktop\SCANNER\evidence\screenshots\csrf\step_010_csrf_form_evidence_1a0ac5.png`*

#### HTTP Request Evidence
```http
GET http://demo.testfire.net/bank/main.jsp
host: demo.testfire.net
accept-encoding: gzip, deflate
connection: keep-alive
user-agent: DAST-Security-Auditor/1.0 (+authorized-security-assessment)
accept: */*
cookie: JSESSIONID=4F0B4AB10DD4DD22B9B11DA8BDA795BC; AltoroAccounts=ODAwMDAyflNhdmluZ3N+LTguOTk5OTk3NDMyMDM3Nzc1RTI2fDgwMDAwM35DaGVja2luZ345LjAwMDAxNzc1MjQ1MTcwN0UyNnw0NTM5MDgyMDM5Mzk2Mjg4fkNyZWRpdCBDYXJkfi0xLjE4NDQ2NzQ0MDc4MDA1NjVFMjB8ODAwMDExfkNoZWNraW5nfjEuOTk5OTk5ODQ0ODJFMTF8ODAwMDEzfkNoZWNraW5nfjQwMC4wfDgwMDAxNH5TYXZpbmdzfi00NDc1LjB8ODAwMDE1fklSQX41MDAwLjB8ODAwMDE2flNhdmluZ3N+MC4wfDgwMDAxN35TYXZpbmdzfjAuMHw4MDAwMTh+U2F2aW5nc34wLjB8ODAwMDE5flNhdmluZ3N+MC4wfDgwMDAyMH5TYXZpbmdzfjEuMDY2MDIwNjk2Njk3NzQ1OEUyMXw4MDAwMjF+Q2hlY2tpbmd+MTcwLjB8
authorization: Basic anNtaXRoOmRlbW8xMjM0


```

#### HTTP Response Evidence
```http
HTTP/1.1 200 (941.3ms)
server: Apache-Coyote/1.1
content-type: text/html;charset=ISO-8859-1
content-length: 6489
date: Fri, 09 Oct 2026 08:33:28 GMT



 
    

 

<!-- BEGIN HEADER -->
<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">

<html xmlns="http://www.w3.org/1999/xhtml" xml:lang="en" >



<head>
	<title>Altoro Mutual</title>
  <meta http-equiv="Content-Type" content="text/html; charset=iso-8859-1" />
  <link href="/style.css" rel="stylesheet" type="text/css" />
</head>
<body style="margin-top:5px;">

<div id="header" style="margin-bottom:5px; width: 99%;">
  <form
```

#### Remediation
> 1. Convert sensitive state-changing actions from HTTP GET to HTTP POST.
2. Include cryptographically random, unpredictable anti-CSRF tokens in all state-changing HTML forms.
3. Enforce 'SameSite=Lax' or 'SameSite=Strict' on session cookies.
4. Require re-authentication (current password) for critical account actions (e.g., password change, email change).

---

### 28. [MEDIUM] Missing Security Header: Content-Security-Policy

* **Detector Plugin:** `security_headers`
* **Evidence Type:** `http_traffic`
* **Affected URL:** `GET http://demo.testfire.net/bank/main.jsp`

#### Description
Protects against Cross-Site Scripting (XSS), data injection, and clickjacking attacks.

#### Technical Evidence
```text
HTTP Traffic Evidence:
Missing Recommended Security Header: Content-Security-Policy
Status Code: 200
Observed Headers: content-length, content-type, date, server
```

#### HTTP Request Evidence
```http
GET http://demo.testfire.net/bank/main.jsp
host: demo.testfire.net
accept-encoding: gzip, deflate
connection: keep-alive
user-agent: DAST-Security-Auditor/1.0 (+authorized-security-assessment)
accept: */*
cookie: JSESSIONID=4F0B4AB10DD4DD22B9B11DA8BDA795BC; AltoroAccounts=ODAwMDAyflNhdmluZ3N+LTguOTk5OTk3NDMyMDM3Nzc1RTI2fDgwMDAwM35DaGVja2luZ345LjAwMDAxNzc1MjQ1MTcwN0UyNnw0NTM5MDgyMDM5Mzk2Mjg4fkNyZWRpdCBDYXJkfi0xLjE4NDQ2NzQ0MDc4MDA1NjVFMjB8ODAwMDExfkNoZWNraW5nfjEuOTk5OTk5ODQ0ODJFMTF8ODAwMDEzfkNoZWNraW5nfjQwMC4wfDgwMDAxNH5TYXZpbmdzfi00NDc1LjB8ODAwMDE1fklSQX41MDAwLjB8ODAwMDE2flNhdmluZ3N+MC4wfDgwMDAxN35TYXZpbmdzfjAuMHw4MDAwMTh+U2F2aW5nc34wLjB8ODAwMDE5flNhdmluZ3N+MC4wfDgwMDAyMH5TYXZpbmdzfjEuMDY2MDIwNjk2Njk3NzQ1OEUyMXw4MDAwMjF+Q2hlY2tpbmd+MTcwLjB8
authorization: Basic anNtaXRoOmRlbW8xMjM0


```

#### HTTP Response Evidence
```http
HTTP/1.1 200 (311.5ms)
server: Apache-Coyote/1.1
content-type: text/html;charset=ISO-8859-1
content-length: 6489
date: Fri, 09 Oct 2026 08:33:33 GMT



 
    

 

<!-- BEGIN HEADER -->
<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">

<html xmlns="http://www.w3.org/1999/xhtml" xml:lang="en" >



<head>
	<title>Altoro Mutual</title>
  <meta http-equiv="Content-Type" content="text/html; charset=iso-8859-1" />
  <link href="/style.css" rel="stylesheet" type="text/css" />
</head>
<body style="margin-top:5px;">

<div id="header" style="margin-bottom:5px; width: 99%;">
  <form
```

#### Remediation
> Define and enforce a strict Content-Security-Policy (CSP) restricting trusted sources.

---

### 29. [MEDIUM] Missing Security Header: X-Frame-Options

* **Detector Plugin:** `security_headers`
* **Evidence Type:** `http_traffic`
* **Affected URL:** `GET http://demo.testfire.net/bank/main.jsp`

#### Description
Defends against UI redress attacks (Clickjacking) by disallowing framing.

#### Technical Evidence
```text
HTTP Traffic Evidence:
Missing Recommended Security Header: X-Frame-Options
Status Code: 200
Observed Headers: content-length, content-type, date, server
```

#### HTTP Request Evidence
```http
GET http://demo.testfire.net/bank/main.jsp
host: demo.testfire.net
accept-encoding: gzip, deflate
connection: keep-alive
user-agent: DAST-Security-Auditor/1.0 (+authorized-security-assessment)
accept: */*
cookie: JSESSIONID=4F0B4AB10DD4DD22B9B11DA8BDA795BC; AltoroAccounts=ODAwMDAyflNhdmluZ3N+LTguOTk5OTk3NDMyMDM3Nzc1RTI2fDgwMDAwM35DaGVja2luZ345LjAwMDAxNzc1MjQ1MTcwN0UyNnw0NTM5MDgyMDM5Mzk2Mjg4fkNyZWRpdCBDYXJkfi0xLjE4NDQ2NzQ0MDc4MDA1NjVFMjB8ODAwMDExfkNoZWNraW5nfjEuOTk5OTk5ODQ0ODJFMTF8ODAwMDEzfkNoZWNraW5nfjQwMC4wfDgwMDAxNH5TYXZpbmdzfi00NDc1LjB8ODAwMDE1fklSQX41MDAwLjB8ODAwMDE2flNhdmluZ3N+MC4wfDgwMDAxN35TYXZpbmdzfjAuMHw4MDAwMTh+U2F2aW5nc34wLjB8ODAwMDE5flNhdmluZ3N+MC4wfDgwMDAyMH5TYXZpbmdzfjEuMDY2MDIwNjk2Njk3NzQ1OEUyMXw4MDAwMjF+Q2hlY2tpbmd+MTcwLjB8
authorization: Basic anNtaXRoOmRlbW8xMjM0


```

#### HTTP Response Evidence
```http
HTTP/1.1 200 (311.5ms)
server: Apache-Coyote/1.1
content-type: text/html;charset=ISO-8859-1
content-length: 6489
date: Fri, 09 Oct 2026 08:33:33 GMT



 
    

 

<!-- BEGIN HEADER -->
<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">

<html xmlns="http://www.w3.org/1999/xhtml" xml:lang="en" >



<head>
	<title>Altoro Mutual</title>
  <meta http-equiv="Content-Type" content="text/html; charset=iso-8859-1" />
  <link href="/style.css" rel="stylesheet" type="text/css" />
</head>
<body style="margin-top:5px;">

<div id="header" style="margin-bottom:5px; width: 99%;">
  <form
```

#### Remediation
> Set X-Frame-Options to DENY or SAMEORIGIN.

---

### 30. [LOW] Missing Security Header: X-Content-Type-Options

* **Detector Plugin:** `security_headers`
* **Evidence Type:** `http_traffic`
* **Affected URL:** `GET http://demo.testfire.net/bank/main.jsp`

#### Description
Prevents MIME-type sniffing which can lead to script execution via non-executable files.

#### Technical Evidence
```text
HTTP Traffic Evidence:
Missing Recommended Security Header: X-Content-Type-Options
Status Code: 200
Observed Headers: content-length, content-type, date, server
```

#### HTTP Request Evidence
```http
GET http://demo.testfire.net/bank/main.jsp
host: demo.testfire.net
accept-encoding: gzip, deflate
connection: keep-alive
user-agent: DAST-Security-Auditor/1.0 (+authorized-security-assessment)
accept: */*
cookie: JSESSIONID=4F0B4AB10DD4DD22B9B11DA8BDA795BC; AltoroAccounts=ODAwMDAyflNhdmluZ3N+LTguOTk5OTk3NDMyMDM3Nzc1RTI2fDgwMDAwM35DaGVja2luZ345LjAwMDAxNzc1MjQ1MTcwN0UyNnw0NTM5MDgyMDM5Mzk2Mjg4fkNyZWRpdCBDYXJkfi0xLjE4NDQ2NzQ0MDc4MDA1NjVFMjB8ODAwMDExfkNoZWNraW5nfjEuOTk5OTk5ODQ0ODJFMTF8ODAwMDEzfkNoZWNraW5nfjQwMC4wfDgwMDAxNH5TYXZpbmdzfi00NDc1LjB8ODAwMDE1fklSQX41MDAwLjB8ODAwMDE2flNhdmluZ3N+MC4wfDgwMDAxN35TYXZpbmdzfjAuMHw4MDAwMTh+U2F2aW5nc34wLjB8ODAwMDE5flNhdmluZ3N+MC4wfDgwMDAyMH5TYXZpbmdzfjEuMDY2MDIwNjk2Njk3NzQ1OEUyMXw4MDAwMjF+Q2hlY2tpbmd+MTcwLjB8
authorization: Basic anNtaXRoOmRlbW8xMjM0


```

#### HTTP Response Evidence
```http
HTTP/1.1 200 (311.5ms)
server: Apache-Coyote/1.1
content-type: text/html;charset=ISO-8859-1
content-length: 6489
date: Fri, 09 Oct 2026 08:33:33 GMT



 
    

 

<!-- BEGIN HEADER -->
<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">

<html xmlns="http://www.w3.org/1999/xhtml" xml:lang="en" >



<head>
	<title>Altoro Mutual</title>
  <meta http-equiv="Content-Type" content="text/html; charset=iso-8859-1" />
  <link href="/style.css" rel="stylesheet" type="text/css" />
</head>
<body style="margin-top:5px;">

<div id="header" style="margin-bottom:5px; width: 99%;">
  <form
```

#### Remediation
> Set X-Content-Type-Options to 'nosniff'.

---

### 31. [LOW] Missing Security Header: Referrer-Policy

* **Detector Plugin:** `security_headers`
* **Evidence Type:** `http_traffic`
* **Affected URL:** `GET http://demo.testfire.net/bank/main.jsp`

#### Description
Protects sensitive URLs and query parameters from leaking via the HTTP Referer header.

#### Technical Evidence
```text
HTTP Traffic Evidence:
Missing Recommended Security Header: Referrer-Policy
Status Code: 200
Observed Headers: content-length, content-type, date, server
```

#### HTTP Request Evidence
```http
GET http://demo.testfire.net/bank/main.jsp
host: demo.testfire.net
accept-encoding: gzip, deflate
connection: keep-alive
user-agent: DAST-Security-Auditor/1.0 (+authorized-security-assessment)
accept: */*
cookie: JSESSIONID=4F0B4AB10DD4DD22B9B11DA8BDA795BC; AltoroAccounts=ODAwMDAyflNhdmluZ3N+LTguOTk5OTk3NDMyMDM3Nzc1RTI2fDgwMDAwM35DaGVja2luZ345LjAwMDAxNzc1MjQ1MTcwN0UyNnw0NTM5MDgyMDM5Mzk2Mjg4fkNyZWRpdCBDYXJkfi0xLjE4NDQ2NzQ0MDc4MDA1NjVFMjB8ODAwMDExfkNoZWNraW5nfjEuOTk5OTk5ODQ0ODJFMTF8ODAwMDEzfkNoZWNraW5nfjQwMC4wfDgwMDAxNH5TYXZpbmdzfi00NDc1LjB8ODAwMDE1fklSQX41MDAwLjB8ODAwMDE2flNhdmluZ3N+MC4wfDgwMDAxN35TYXZpbmdzfjAuMHw4MDAwMTh+U2F2aW5nc34wLjB8ODAwMDE5flNhdmluZ3N+MC4wfDgwMDAyMH5TYXZpbmdzfjEuMDY2MDIwNjk2Njk3NzQ1OEUyMXw4MDAwMjF+Q2hlY2tpbmd+MTcwLjB8
authorization: Basic anNtaXRoOmRlbW8xMjM0


```

#### HTTP Response Evidence
```http
HTTP/1.1 200 (311.5ms)
server: Apache-Coyote/1.1
content-type: text/html;charset=ISO-8859-1
content-length: 6489
date: Fri, 09 Oct 2026 08:33:33 GMT



 
    

 

<!-- BEGIN HEADER -->
<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">

<html xmlns="http://www.w3.org/1999/xhtml" xml:lang="en" >



<head>
	<title>Altoro Mutual</title>
  <meta http-equiv="Content-Type" content="text/html; charset=iso-8859-1" />
  <link href="/style.css" rel="stylesheet" type="text/css" />
</head>
<body style="margin-top:5px;">

<div id="header" style="margin-bottom:5px; width: 99%;">
  <form
```

#### Remediation
> Configure Referrer-Policy to 'strict-origin-when-cross-origin' or 'no-referrer'.

---

### 32. [LOW] Information Disclosure: Server Header

* **Detector Plugin:** `security_headers`
* **Evidence Type:** `http_traffic`
* **Affected URL:** `GET http://demo.testfire.net/bank/main.jsp`

#### Description
Web server vendor and version banner disclosure: 'Apache-Coyote/1.1' was returned in the server response.

#### Technical Evidence
```text
HTTP Traffic Evidence:
Disclosed Header: Server: Apache-Coyote/1.1
Status Code: 200
```

#### HTTP Request Evidence
```http
GET http://demo.testfire.net/bank/main.jsp
host: demo.testfire.net
accept-encoding: gzip, deflate
connection: keep-alive
user-agent: DAST-Security-Auditor/1.0 (+authorized-security-assessment)
accept: */*
cookie: JSESSIONID=4F0B4AB10DD4DD22B9B11DA8BDA795BC; AltoroAccounts=ODAwMDAyflNhdmluZ3N+LTguOTk5OTk3NDMyMDM3Nzc1RTI2fDgwMDAwM35DaGVja2luZ345LjAwMDAxNzc1MjQ1MTcwN0UyNnw0NTM5MDgyMDM5Mzk2Mjg4fkNyZWRpdCBDYXJkfi0xLjE4NDQ2NzQ0MDc4MDA1NjVFMjB8ODAwMDExfkNoZWNraW5nfjEuOTk5OTk5ODQ0ODJFMTF8ODAwMDEzfkNoZWNraW5nfjQwMC4wfDgwMDAxNH5TYXZpbmdzfi00NDc1LjB8ODAwMDE1fklSQX41MDAwLjB8ODAwMDE2flNhdmluZ3N+MC4wfDgwMDAxN35TYXZpbmdzfjAuMHw4MDAwMTh+U2F2aW5nc34wLjB8ODAwMDE5flNhdmluZ3N+MC4wfDgwMDAyMH5TYXZpbmdzfjEuMDY2MDIwNjk2Njk3NzQ1OEUyMXw4MDAwMjF+Q2hlY2tpbmd+MTcwLjB8
authorization: Basic anNtaXRoOmRlbW8xMjM0


```

#### HTTP Response Evidence
```http
HTTP/1.1 200 (311.5ms)
server: Apache-Coyote/1.1
content-type: text/html;charset=ISO-8859-1
content-length: 6489
date: Fri, 09 Oct 2026 08:33:33 GMT



 
    

 

<!-- BEGIN HEADER -->
<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">

<html xmlns="http://www.w3.org/1999/xhtml" xml:lang="en" >



<head>
	<title>Altoro Mutual</title>
  <meta http-equiv="Content-Type" content="text/html; charset=iso-8859-1" />
  <link href="/style.css" rel="stylesheet" type="text/css" />
</head>
<body style="margin-top:5px;">

<div id="header" style="margin-bottom:5px; width: 99%;">
  <form
```

#### Remediation
> Configure the web server or reverse proxy to strip or suppress the Server header.

---

### 33. [HIGH] Reflected Cross-Site Scripting (XSS) in Form Field 'query'

* **Detector Plugin:** `xss`
* **Evidence Type:** `screenshot`
* **Affected URL:** `GET http://demo.testfire.net/search.jsp` `[query]`

#### Description
Form field 'query' is vulnerable to reflected Cross-Site Scripting (XSS).

#### Technical Evidence
```text
Visual XSS confirmed. Injected payload '<script>document.body.style.backgroundColor='red';document.body.insertAdjacentHTML('afterbegin','<h1>dastXSS</h1>')</script>' executed in DOM with visual indicators.
```

#### Visual Screenshot Evidence
![Screenshot Evidence](C:\Users\HP\OneDrive\Desktop\SCANNER\evidence\screenshots\xss\step_011_xss_query_evidence_f1f64e.png)
*File Path: `C:\Users\HP\OneDrive\Desktop\SCANNER\evidence\screenshots\xss\step_011_xss_query_evidence_f1f64e.png`*

#### Remediation
> Contextually encode all user-supplied output (e.g. HTML entity encoding) and enforce a strict CSP.

---

### 34. [MEDIUM] Missing Security Header: Content-Security-Policy

* **Detector Plugin:** `security_headers`
* **Evidence Type:** `http_traffic`
* **Affected URL:** `GET http://demo.testfire.net/style.css`

#### Description
Protects against Cross-Site Scripting (XSS), data injection, and clickjacking attacks.

#### Technical Evidence
```text
HTTP Traffic Evidence:
Missing Recommended Security Header: Content-Security-Policy
Status Code: 200
Observed Headers: accept-ranges, content-length, content-type, date, etag, last-modified, server
```

#### HTTP Request Evidence
```http
GET http://demo.testfire.net/style.css
host: demo.testfire.net
accept-encoding: gzip, deflate
connection: keep-alive
user-agent: DAST-Security-Auditor/1.0 (+authorized-security-assessment)
accept: */*
cookie: JSESSIONID=4F0B4AB10DD4DD22B9B11DA8BDA795BC; AltoroAccounts=ODAwMDAyflNhdmluZ3N+LTguOTk5OTk3NDMyMDM3Nzc1RTI2fDgwMDAwM35DaGVja2luZ345LjAwMDAxNzc1MjQ1MTcwN0UyNnw0NTM5MDgyMDM5Mzk2Mjg4fkNyZWRpdCBDYXJkfi0xLjE4NDQ2NzQ0MDc4MDA1NjVFMjB8ODAwMDExfkNoZWNraW5nfjEuOTk5OTk5ODQ0ODJFMTF8ODAwMDEzfkNoZWNraW5nfjQwMC4wfDgwMDAxNH5TYXZpbmdzfi00NDc1LjB8ODAwMDE1fklSQX41MDAwLjB8ODAwMDE2flNhdmluZ3N+MC4wfDgwMDAxN35TYXZpbmdzfjAuMHw4MDAwMTh+U2F2aW5nc34wLjB8ODAwMDE5flNhdmluZ3N+MC4wfDgwMDAyMH5TYXZpbmdzfjEuMDY2MDIwNjk2Njk3NzQ1OEUyMXw4MDAwMjF+Q2hlY2tpbmd+MTcwLjB8
authorization: Basic anNtaXRoOmRlbW8xMjM0


```

#### HTTP Response Evidence
```http
HTTP/1.1 200 (287.3ms)
server: Apache-Coyote/1.1
accept-ranges: bytes
etag: W/"1165-1785257390000"
last-modified: Tue, 28 Jul 2026 16:49:50 GMT
content-type: text/css
content-length: 1165
date: Fri, 09 Oct 2026 08:34:07 GMT

body, table, td, p  {
	color:#000000;
	font: 10px Verdana, Arial, Sans-Serif;
	line-height: 1.6;
}
img {
	border-style: none;
	border-width: 0px;
}
form {
	margin-top: 0;
	margin-bottom: 0;
}
ul, ol {
	margin-top: 2px;
	margin-bottom: 8px;
}
td, p {
	margin: 10px;
	padding: 3px 10px 3px 10px;
}
th {
	text-align: left;
}
input {
	color:#333366;
	font: 11px Verdana, Arial, Sans-Serif;
}
h1 {
	color:#00796C;
	font: 22px Verdana, Arial, Sans-Serif;
	font-weight: bold;
	margin-top: 0px;
	padding-top:
```

#### Remediation
> Define and enforce a strict Content-Security-Policy (CSP) restricting trusted sources.

---

### 35. [MEDIUM] Missing Security Header: X-Frame-Options

* **Detector Plugin:** `security_headers`
* **Evidence Type:** `http_traffic`
* **Affected URL:** `GET http://demo.testfire.net/style.css`

#### Description
Defends against UI redress attacks (Clickjacking) by disallowing framing.

#### Technical Evidence
```text
HTTP Traffic Evidence:
Missing Recommended Security Header: X-Frame-Options
Status Code: 200
Observed Headers: accept-ranges, content-length, content-type, date, etag, last-modified, server
```

#### HTTP Request Evidence
```http
GET http://demo.testfire.net/style.css
host: demo.testfire.net
accept-encoding: gzip, deflate
connection: keep-alive
user-agent: DAST-Security-Auditor/1.0 (+authorized-security-assessment)
accept: */*
cookie: JSESSIONID=4F0B4AB10DD4DD22B9B11DA8BDA795BC; AltoroAccounts=ODAwMDAyflNhdmluZ3N+LTguOTk5OTk3NDMyMDM3Nzc1RTI2fDgwMDAwM35DaGVja2luZ345LjAwMDAxNzc1MjQ1MTcwN0UyNnw0NTM5MDgyMDM5Mzk2Mjg4fkNyZWRpdCBDYXJkfi0xLjE4NDQ2NzQ0MDc4MDA1NjVFMjB8ODAwMDExfkNoZWNraW5nfjEuOTk5OTk5ODQ0ODJFMTF8ODAwMDEzfkNoZWNraW5nfjQwMC4wfDgwMDAxNH5TYXZpbmdzfi00NDc1LjB8ODAwMDE1fklSQX41MDAwLjB8ODAwMDE2flNhdmluZ3N+MC4wfDgwMDAxN35TYXZpbmdzfjAuMHw4MDAwMTh+U2F2aW5nc34wLjB8ODAwMDE5flNhdmluZ3N+MC4wfDgwMDAyMH5TYXZpbmdzfjEuMDY2MDIwNjk2Njk3NzQ1OEUyMXw4MDAwMjF+Q2hlY2tpbmd+MTcwLjB8
authorization: Basic anNtaXRoOmRlbW8xMjM0


```

#### HTTP Response Evidence
```http
HTTP/1.1 200 (287.3ms)
server: Apache-Coyote/1.1
accept-ranges: bytes
etag: W/"1165-1785257390000"
last-modified: Tue, 28 Jul 2026 16:49:50 GMT
content-type: text/css
content-length: 1165
date: Fri, 09 Oct 2026 08:34:07 GMT

body, table, td, p  {
	color:#000000;
	font: 10px Verdana, Arial, Sans-Serif;
	line-height: 1.6;
}
img {
	border-style: none;
	border-width: 0px;
}
form {
	margin-top: 0;
	margin-bottom: 0;
}
ul, ol {
	margin-top: 2px;
	margin-bottom: 8px;
}
td, p {
	margin: 10px;
	padding: 3px 10px 3px 10px;
}
th {
	text-align: left;
}
input {
	color:#333366;
	font: 11px Verdana, Arial, Sans-Serif;
}
h1 {
	color:#00796C;
	font: 22px Verdana, Arial, Sans-Serif;
	font-weight: bold;
	margin-top: 0px;
	padding-top:
```

#### Remediation
> Set X-Frame-Options to DENY or SAMEORIGIN.

---

### 36. [LOW] Missing Security Header: X-Content-Type-Options

* **Detector Plugin:** `security_headers`
* **Evidence Type:** `http_traffic`
* **Affected URL:** `GET http://demo.testfire.net/style.css`

#### Description
Prevents MIME-type sniffing which can lead to script execution via non-executable files.

#### Technical Evidence
```text
HTTP Traffic Evidence:
Missing Recommended Security Header: X-Content-Type-Options
Status Code: 200
Observed Headers: accept-ranges, content-length, content-type, date, etag, last-modified, server
```

#### HTTP Request Evidence
```http
GET http://demo.testfire.net/style.css
host: demo.testfire.net
accept-encoding: gzip, deflate
connection: keep-alive
user-agent: DAST-Security-Auditor/1.0 (+authorized-security-assessment)
accept: */*
cookie: JSESSIONID=4F0B4AB10DD4DD22B9B11DA8BDA795BC; AltoroAccounts=ODAwMDAyflNhdmluZ3N+LTguOTk5OTk3NDMyMDM3Nzc1RTI2fDgwMDAwM35DaGVja2luZ345LjAwMDAxNzc1MjQ1MTcwN0UyNnw0NTM5MDgyMDM5Mzk2Mjg4fkNyZWRpdCBDYXJkfi0xLjE4NDQ2NzQ0MDc4MDA1NjVFMjB8ODAwMDExfkNoZWNraW5nfjEuOTk5OTk5ODQ0ODJFMTF8ODAwMDEzfkNoZWNraW5nfjQwMC4wfDgwMDAxNH5TYXZpbmdzfi00NDc1LjB8ODAwMDE1fklSQX41MDAwLjB8ODAwMDE2flNhdmluZ3N+MC4wfDgwMDAxN35TYXZpbmdzfjAuMHw4MDAwMTh+U2F2aW5nc34wLjB8ODAwMDE5flNhdmluZ3N+MC4wfDgwMDAyMH5TYXZpbmdzfjEuMDY2MDIwNjk2Njk3NzQ1OEUyMXw4MDAwMjF+Q2hlY2tpbmd+MTcwLjB8
authorization: Basic anNtaXRoOmRlbW8xMjM0


```

#### HTTP Response Evidence
```http
HTTP/1.1 200 (287.3ms)
server: Apache-Coyote/1.1
accept-ranges: bytes
etag: W/"1165-1785257390000"
last-modified: Tue, 28 Jul 2026 16:49:50 GMT
content-type: text/css
content-length: 1165
date: Fri, 09 Oct 2026 08:34:07 GMT

body, table, td, p  {
	color:#000000;
	font: 10px Verdana, Arial, Sans-Serif;
	line-height: 1.6;
}
img {
	border-style: none;
	border-width: 0px;
}
form {
	margin-top: 0;
	margin-bottom: 0;
}
ul, ol {
	margin-top: 2px;
	margin-bottom: 8px;
}
td, p {
	margin: 10px;
	padding: 3px 10px 3px 10px;
}
th {
	text-align: left;
}
input {
	color:#333366;
	font: 11px Verdana, Arial, Sans-Serif;
}
h1 {
	color:#00796C;
	font: 22px Verdana, Arial, Sans-Serif;
	font-weight: bold;
	margin-top: 0px;
	padding-top:
```

#### Remediation
> Set X-Content-Type-Options to 'nosniff'.

---

### 37. [LOW] Missing Security Header: Referrer-Policy

* **Detector Plugin:** `security_headers`
* **Evidence Type:** `http_traffic`
* **Affected URL:** `GET http://demo.testfire.net/style.css`

#### Description
Protects sensitive URLs and query parameters from leaking via the HTTP Referer header.

#### Technical Evidence
```text
HTTP Traffic Evidence:
Missing Recommended Security Header: Referrer-Policy
Status Code: 200
Observed Headers: accept-ranges, content-length, content-type, date, etag, last-modified, server
```

#### HTTP Request Evidence
```http
GET http://demo.testfire.net/style.css
host: demo.testfire.net
accept-encoding: gzip, deflate
connection: keep-alive
user-agent: DAST-Security-Auditor/1.0 (+authorized-security-assessment)
accept: */*
cookie: JSESSIONID=4F0B4AB10DD4DD22B9B11DA8BDA795BC; AltoroAccounts=ODAwMDAyflNhdmluZ3N+LTguOTk5OTk3NDMyMDM3Nzc1RTI2fDgwMDAwM35DaGVja2luZ345LjAwMDAxNzc1MjQ1MTcwN0UyNnw0NTM5MDgyMDM5Mzk2Mjg4fkNyZWRpdCBDYXJkfi0xLjE4NDQ2NzQ0MDc4MDA1NjVFMjB8ODAwMDExfkNoZWNraW5nfjEuOTk5OTk5ODQ0ODJFMTF8ODAwMDEzfkNoZWNraW5nfjQwMC4wfDgwMDAxNH5TYXZpbmdzfi00NDc1LjB8ODAwMDE1fklSQX41MDAwLjB8ODAwMDE2flNhdmluZ3N+MC4wfDgwMDAxN35TYXZpbmdzfjAuMHw4MDAwMTh+U2F2aW5nc34wLjB8ODAwMDE5flNhdmluZ3N+MC4wfDgwMDAyMH5TYXZpbmdzfjEuMDY2MDIwNjk2Njk3NzQ1OEUyMXw4MDAwMjF+Q2hlY2tpbmd+MTcwLjB8
authorization: Basic anNtaXRoOmRlbW8xMjM0


```

#### HTTP Response Evidence
```http
HTTP/1.1 200 (287.3ms)
server: Apache-Coyote/1.1
accept-ranges: bytes
etag: W/"1165-1785257390000"
last-modified: Tue, 28 Jul 2026 16:49:50 GMT
content-type: text/css
content-length: 1165
date: Fri, 09 Oct 2026 08:34:07 GMT

body, table, td, p  {
	color:#000000;
	font: 10px Verdana, Arial, Sans-Serif;
	line-height: 1.6;
}
img {
	border-style: none;
	border-width: 0px;
}
form {
	margin-top: 0;
	margin-bottom: 0;
}
ul, ol {
	margin-top: 2px;
	margin-bottom: 8px;
}
td, p {
	margin: 10px;
	padding: 3px 10px 3px 10px;
}
th {
	text-align: left;
}
input {
	color:#333366;
	font: 11px Verdana, Arial, Sans-Serif;
}
h1 {
	color:#00796C;
	font: 22px Verdana, Arial, Sans-Serif;
	font-weight: bold;
	margin-top: 0px;
	padding-top:
```

#### Remediation
> Configure Referrer-Policy to 'strict-origin-when-cross-origin' or 'no-referrer'.

---

### 38. [LOW] Information Disclosure: Server Header

* **Detector Plugin:** `security_headers`
* **Evidence Type:** `http_traffic`
* **Affected URL:** `GET http://demo.testfire.net/style.css`

#### Description
Web server vendor and version banner disclosure: 'Apache-Coyote/1.1' was returned in the server response.

#### Technical Evidence
```text
HTTP Traffic Evidence:
Disclosed Header: Server: Apache-Coyote/1.1
Status Code: 200
```

#### HTTP Request Evidence
```http
GET http://demo.testfire.net/style.css
host: demo.testfire.net
accept-encoding: gzip, deflate
connection: keep-alive
user-agent: DAST-Security-Auditor/1.0 (+authorized-security-assessment)
accept: */*
cookie: JSESSIONID=4F0B4AB10DD4DD22B9B11DA8BDA795BC; AltoroAccounts=ODAwMDAyflNhdmluZ3N+LTguOTk5OTk3NDMyMDM3Nzc1RTI2fDgwMDAwM35DaGVja2luZ345LjAwMDAxNzc1MjQ1MTcwN0UyNnw0NTM5MDgyMDM5Mzk2Mjg4fkNyZWRpdCBDYXJkfi0xLjE4NDQ2NzQ0MDc4MDA1NjVFMjB8ODAwMDExfkNoZWNraW5nfjEuOTk5OTk5ODQ0ODJFMTF8ODAwMDEzfkNoZWNraW5nfjQwMC4wfDgwMDAxNH5TYXZpbmdzfi00NDc1LjB8ODAwMDE1fklSQX41MDAwLjB8ODAwMDE2flNhdmluZ3N+MC4wfDgwMDAxN35TYXZpbmdzfjAuMHw4MDAwMTh+U2F2aW5nc34wLjB8ODAwMDE5flNhdmluZ3N+MC4wfDgwMDAyMH5TYXZpbmdzfjEuMDY2MDIwNjk2Njk3NzQ1OEUyMXw4MDAwMjF+Q2hlY2tpbmd+MTcwLjB8
authorization: Basic anNtaXRoOmRlbW8xMjM0


```

#### HTTP Response Evidence
```http
HTTP/1.1 200 (287.3ms)
server: Apache-Coyote/1.1
accept-ranges: bytes
etag: W/"1165-1785257390000"
last-modified: Tue, 28 Jul 2026 16:49:50 GMT
content-type: text/css
content-length: 1165
date: Fri, 09 Oct 2026 08:34:07 GMT

body, table, td, p  {
	color:#000000;
	font: 10px Verdana, Arial, Sans-Serif;
	line-height: 1.6;
}
img {
	border-style: none;
	border-width: 0px;
}
form {
	margin-top: 0;
	margin-bottom: 0;
}
ul, ol {
	margin-top: 2px;
	margin-bottom: 8px;
}
td, p {
	margin: 10px;
	padding: 3px 10px 3px 10px;
}
th {
	text-align: left;
}
input {
	color:#333366;
	font: 11px Verdana, Arial, Sans-Serif;
}
h1 {
	color:#00796C;
	font: 22px Verdana, Arial, Sans-Serif;
	font-weight: bold;
	margin-top: 0px;
	padding-top:
```

#### Remediation
> Configure the web server or reverse proxy to strip or suppress the Server header.

---

### 39. [MEDIUM] Missing Clickjacking Defensive Framing Protections

* **Detector Plugin:** `clickjacking`
* **Evidence Type:** `http_traffic`
* **Affected URL:** `GET http://demo.testfire.net/index.jsp`

#### Description
The page lacks both the X-Frame-Options header and CSP frame-ancestors directive. An attacker can frame this target within a transparent <iframe> on a malicious domain to trick authenticated users into clicking sensitive UI buttons (Clickjacking).

#### Technical Evidence
```text
HTTP Response Header Evidence:
X-Frame-Options Header: Missing
CSP frame-ancestors Directive: Missing
```

#### HTTP Request Evidence
```http
GET http://demo.testfire.net/index.jsp
host: demo.testfire.net
accept-encoding: gzip, deflate
connection: keep-alive
user-agent: DAST-Security-Auditor/1.0 (+authorized-security-assessment)
accept: */*
cookie: JSESSIONID=4F0B4AB10DD4DD22B9B11DA8BDA795BC; AltoroAccounts=ODAwMDAyflNhdmluZ3N+LTguOTk5OTk3NDMyMDM3Nzc1RTI2fDgwMDAwM35DaGVja2luZ345LjAwMDAxNzc1MjQ1MTcwN0UyNnw0NTM5MDgyMDM5Mzk2Mjg4fkNyZWRpdCBDYXJkfi0xLjE4NDQ2NzQ0MDc4MDA1NjVFMjB8ODAwMDExfkNoZWNraW5nfjEuOTk5OTk5ODQ0ODJFMTF8ODAwMDEzfkNoZWNraW5nfjQwMC4wfDgwMDAxNH5TYXZpbmdzfi00NDc1LjB8ODAwMDE1fklSQX41MDAwLjB8ODAwMDE2flNhdmluZ3N+MC4wfDgwMDAxN35TYXZpbmdzfjAuMHw4MDAwMTh+U2F2aW5nc34wLjB8ODAwMDE5flNhdmluZ3N+MC4wfDgwMDAyMH5TYXZpbmdzfjEuMDY2MDIwNjk2Njk3NzQ1OEUyMXw4MDAwMjF+Q2hlY2tpbmd+MTcwLjB8
authorization: Basic anNtaXRoOmRlbW8xMjM0


```

#### HTTP Response Evidence
```http
HTTP/1.1 200 (287.6ms)
server: Apache-Coyote/1.1
content-type: text/html;charset=ISO-8859-1
transfer-encoding: chunked
date: Fri, 09 Oct 2026 08:34:07 GMT







 
    

 

<!-- BEGIN HEADER -->
<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">

<html xmlns="http://www.w3.org/1999/xhtml" xml:lang="en" >



<head>
	<title>Altoro Mutual</title>
  <meta http-equiv="Content-Type" content="text/html; charset=iso-8859-1" />
  <link href="/style.css" rel="stylesheet" type="text/css" />
</head>
<body style="margin-top:5px;">

<div id="header" style="margin-bottom:5px; width: 99%;">
  <
```

#### Remediation
> Set 'X-Frame-Options: SAMEORIGIN' or 'Content-Security-Policy: frame-ancestors 'self''.

---

### 40. [MEDIUM] Missing Security Header: Content-Security-Policy

* **Detector Plugin:** `security_headers`
* **Evidence Type:** `http_traffic`
* **Affected URL:** `GET http://demo.testfire.net/index.jsp`

#### Description
Protects against Cross-Site Scripting (XSS), data injection, and clickjacking attacks.

#### Technical Evidence
```text
HTTP Traffic Evidence:
Missing Recommended Security Header: Content-Security-Policy
Status Code: 200
Observed Headers: content-type, date, server, transfer-encoding
```

#### HTTP Request Evidence
```http
GET http://demo.testfire.net/index.jsp
host: demo.testfire.net
accept-encoding: gzip, deflate
connection: keep-alive
user-agent: DAST-Security-Auditor/1.0 (+authorized-security-assessment)
accept: */*
cookie: JSESSIONID=4F0B4AB10DD4DD22B9B11DA8BDA795BC; AltoroAccounts=ODAwMDAyflNhdmluZ3N+LTguOTk5OTk3NDMyMDM3Nzc1RTI2fDgwMDAwM35DaGVja2luZ345LjAwMDAxNzc1MjQ1MTcwN0UyNnw0NTM5MDgyMDM5Mzk2Mjg4fkNyZWRpdCBDYXJkfi0xLjE4NDQ2NzQ0MDc4MDA1NjVFMjB8ODAwMDExfkNoZWNraW5nfjEuOTk5OTk5ODQ0ODJFMTF8ODAwMDEzfkNoZWNraW5nfjQwMC4wfDgwMDAxNH5TYXZpbmdzfi00NDc1LjB8ODAwMDE1fklSQX41MDAwLjB8ODAwMDE2flNhdmluZ3N+MC4wfDgwMDAxN35TYXZpbmdzfjAuMHw4MDAwMTh+U2F2aW5nc34wLjB8ODAwMDE5flNhdmluZ3N+MC4wfDgwMDAyMH5TYXZpbmdzfjEuMDY2MDIwNjk2Njk3NzQ1OEUyMXw4MDAwMjF+Q2hlY2tpbmd+MTcwLjB8
authorization: Basic anNtaXRoOmRlbW8xMjM0


```

#### HTTP Response Evidence
```http
HTTP/1.1 200 (297.1ms)
server: Apache-Coyote/1.1
content-type: text/html;charset=ISO-8859-1
transfer-encoding: chunked
date: Fri, 09 Oct 2026 08:34:21 GMT







 
    

 

<!-- BEGIN HEADER -->
<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">

<html xmlns="http://www.w3.org/1999/xhtml" xml:lang="en" >



<head>
	<title>Altoro Mutual</title>
  <meta http-equiv="Content-Type" content="text/html; charset=iso-8859-1" />
  <link href="/style.css" rel="stylesheet" type="text/css" />
</head>
<body style="margin-top:5px;">

<div id="header" style="margin-bottom:5px; width: 99%;">
  <
```

#### Remediation
> Define and enforce a strict Content-Security-Policy (CSP) restricting trusted sources.

---

### 41. [MEDIUM] Missing Security Header: X-Frame-Options

* **Detector Plugin:** `security_headers`
* **Evidence Type:** `http_traffic`
* **Affected URL:** `GET http://demo.testfire.net/index.jsp`

#### Description
Defends against UI redress attacks (Clickjacking) by disallowing framing.

#### Technical Evidence
```text
HTTP Traffic Evidence:
Missing Recommended Security Header: X-Frame-Options
Status Code: 200
Observed Headers: content-type, date, server, transfer-encoding
```

#### HTTP Request Evidence
```http
GET http://demo.testfire.net/index.jsp
host: demo.testfire.net
accept-encoding: gzip, deflate
connection: keep-alive
user-agent: DAST-Security-Auditor/1.0 (+authorized-security-assessment)
accept: */*
cookie: JSESSIONID=4F0B4AB10DD4DD22B9B11DA8BDA795BC; AltoroAccounts=ODAwMDAyflNhdmluZ3N+LTguOTk5OTk3NDMyMDM3Nzc1RTI2fDgwMDAwM35DaGVja2luZ345LjAwMDAxNzc1MjQ1MTcwN0UyNnw0NTM5MDgyMDM5Mzk2Mjg4fkNyZWRpdCBDYXJkfi0xLjE4NDQ2NzQ0MDc4MDA1NjVFMjB8ODAwMDExfkNoZWNraW5nfjEuOTk5OTk5ODQ0ODJFMTF8ODAwMDEzfkNoZWNraW5nfjQwMC4wfDgwMDAxNH5TYXZpbmdzfi00NDc1LjB8ODAwMDE1fklSQX41MDAwLjB8ODAwMDE2flNhdmluZ3N+MC4wfDgwMDAxN35TYXZpbmdzfjAuMHw4MDAwMTh+U2F2aW5nc34wLjB8ODAwMDE5flNhdmluZ3N+MC4wfDgwMDAyMH5TYXZpbmdzfjEuMDY2MDIwNjk2Njk3NzQ1OEUyMXw4MDAwMjF+Q2hlY2tpbmd+MTcwLjB8
authorization: Basic anNtaXRoOmRlbW8xMjM0


```

#### HTTP Response Evidence
```http
HTTP/1.1 200 (297.1ms)
server: Apache-Coyote/1.1
content-type: text/html;charset=ISO-8859-1
transfer-encoding: chunked
date: Fri, 09 Oct 2026 08:34:21 GMT







 
    

 

<!-- BEGIN HEADER -->
<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">

<html xmlns="http://www.w3.org/1999/xhtml" xml:lang="en" >



<head>
	<title>Altoro Mutual</title>
  <meta http-equiv="Content-Type" content="text/html; charset=iso-8859-1" />
  <link href="/style.css" rel="stylesheet" type="text/css" />
</head>
<body style="margin-top:5px;">

<div id="header" style="margin-bottom:5px; width: 99%;">
  <
```

#### Remediation
> Set X-Frame-Options to DENY or SAMEORIGIN.

---

### 42. [LOW] Missing Security Header: X-Content-Type-Options

* **Detector Plugin:** `security_headers`
* **Evidence Type:** `http_traffic`
* **Affected URL:** `GET http://demo.testfire.net/index.jsp`

#### Description
Prevents MIME-type sniffing which can lead to script execution via non-executable files.

#### Technical Evidence
```text
HTTP Traffic Evidence:
Missing Recommended Security Header: X-Content-Type-Options
Status Code: 200
Observed Headers: content-type, date, server, transfer-encoding
```

#### HTTP Request Evidence
```http
GET http://demo.testfire.net/index.jsp
host: demo.testfire.net
accept-encoding: gzip, deflate
connection: keep-alive
user-agent: DAST-Security-Auditor/1.0 (+authorized-security-assessment)
accept: */*
cookie: JSESSIONID=4F0B4AB10DD4DD22B9B11DA8BDA795BC; AltoroAccounts=ODAwMDAyflNhdmluZ3N+LTguOTk5OTk3NDMyMDM3Nzc1RTI2fDgwMDAwM35DaGVja2luZ345LjAwMDAxNzc1MjQ1MTcwN0UyNnw0NTM5MDgyMDM5Mzk2Mjg4fkNyZWRpdCBDYXJkfi0xLjE4NDQ2NzQ0MDc4MDA1NjVFMjB8ODAwMDExfkNoZWNraW5nfjEuOTk5OTk5ODQ0ODJFMTF8ODAwMDEzfkNoZWNraW5nfjQwMC4wfDgwMDAxNH5TYXZpbmdzfi00NDc1LjB8ODAwMDE1fklSQX41MDAwLjB8ODAwMDE2flNhdmluZ3N+MC4wfDgwMDAxN35TYXZpbmdzfjAuMHw4MDAwMTh+U2F2aW5nc34wLjB8ODAwMDE5flNhdmluZ3N+MC4wfDgwMDAyMH5TYXZpbmdzfjEuMDY2MDIwNjk2Njk3NzQ1OEUyMXw4MDAwMjF+Q2hlY2tpbmd+MTcwLjB8
authorization: Basic anNtaXRoOmRlbW8xMjM0


```

#### HTTP Response Evidence
```http
HTTP/1.1 200 (297.1ms)
server: Apache-Coyote/1.1
content-type: text/html;charset=ISO-8859-1
transfer-encoding: chunked
date: Fri, 09 Oct 2026 08:34:21 GMT







 
    

 

<!-- BEGIN HEADER -->
<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">

<html xmlns="http://www.w3.org/1999/xhtml" xml:lang="en" >



<head>
	<title>Altoro Mutual</title>
  <meta http-equiv="Content-Type" content="text/html; charset=iso-8859-1" />
  <link href="/style.css" rel="stylesheet" type="text/css" />
</head>
<body style="margin-top:5px;">

<div id="header" style="margin-bottom:5px; width: 99%;">
  <
```

#### Remediation
> Set X-Content-Type-Options to 'nosniff'.

---

### 43. [LOW] Missing Security Header: Referrer-Policy

* **Detector Plugin:** `security_headers`
* **Evidence Type:** `http_traffic`
* **Affected URL:** `GET http://demo.testfire.net/index.jsp`

#### Description
Protects sensitive URLs and query parameters from leaking via the HTTP Referer header.

#### Technical Evidence
```text
HTTP Traffic Evidence:
Missing Recommended Security Header: Referrer-Policy
Status Code: 200
Observed Headers: content-type, date, server, transfer-encoding
```

#### HTTP Request Evidence
```http
GET http://demo.testfire.net/index.jsp
host: demo.testfire.net
accept-encoding: gzip, deflate
connection: keep-alive
user-agent: DAST-Security-Auditor/1.0 (+authorized-security-assessment)
accept: */*
cookie: JSESSIONID=4F0B4AB10DD4DD22B9B11DA8BDA795BC; AltoroAccounts=ODAwMDAyflNhdmluZ3N+LTguOTk5OTk3NDMyMDM3Nzc1RTI2fDgwMDAwM35DaGVja2luZ345LjAwMDAxNzc1MjQ1MTcwN0UyNnw0NTM5MDgyMDM5Mzk2Mjg4fkNyZWRpdCBDYXJkfi0xLjE4NDQ2NzQ0MDc4MDA1NjVFMjB8ODAwMDExfkNoZWNraW5nfjEuOTk5OTk5ODQ0ODJFMTF8ODAwMDEzfkNoZWNraW5nfjQwMC4wfDgwMDAxNH5TYXZpbmdzfi00NDc1LjB8ODAwMDE1fklSQX41MDAwLjB8ODAwMDE2flNhdmluZ3N+MC4wfDgwMDAxN35TYXZpbmdzfjAuMHw4MDAwMTh+U2F2aW5nc34wLjB8ODAwMDE5flNhdmluZ3N+MC4wfDgwMDAyMH5TYXZpbmdzfjEuMDY2MDIwNjk2Njk3NzQ1OEUyMXw4MDAwMjF+Q2hlY2tpbmd+MTcwLjB8
authorization: Basic anNtaXRoOmRlbW8xMjM0


```

#### HTTP Response Evidence
```http
HTTP/1.1 200 (297.1ms)
server: Apache-Coyote/1.1
content-type: text/html;charset=ISO-8859-1
transfer-encoding: chunked
date: Fri, 09 Oct 2026 08:34:21 GMT







 
    

 

<!-- BEGIN HEADER -->
<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">

<html xmlns="http://www.w3.org/1999/xhtml" xml:lang="en" >



<head>
	<title>Altoro Mutual</title>
  <meta http-equiv="Content-Type" content="text/html; charset=iso-8859-1" />
  <link href="/style.css" rel="stylesheet" type="text/css" />
</head>
<body style="margin-top:5px;">

<div id="header" style="margin-bottom:5px; width: 99%;">
  <
```

#### Remediation
> Configure Referrer-Policy to 'strict-origin-when-cross-origin' or 'no-referrer'.

---

### 44. [LOW] Information Disclosure: Server Header

* **Detector Plugin:** `security_headers`
* **Evidence Type:** `http_traffic`
* **Affected URL:** `GET http://demo.testfire.net/index.jsp`

#### Description
Web server vendor and version banner disclosure: 'Apache-Coyote/1.1' was returned in the server response.

#### Technical Evidence
```text
HTTP Traffic Evidence:
Disclosed Header: Server: Apache-Coyote/1.1
Status Code: 200
```

#### HTTP Request Evidence
```http
GET http://demo.testfire.net/index.jsp
host: demo.testfire.net
accept-encoding: gzip, deflate
connection: keep-alive
user-agent: DAST-Security-Auditor/1.0 (+authorized-security-assessment)
accept: */*
cookie: JSESSIONID=4F0B4AB10DD4DD22B9B11DA8BDA795BC; AltoroAccounts=ODAwMDAyflNhdmluZ3N+LTguOTk5OTk3NDMyMDM3Nzc1RTI2fDgwMDAwM35DaGVja2luZ345LjAwMDAxNzc1MjQ1MTcwN0UyNnw0NTM5MDgyMDM5Mzk2Mjg4fkNyZWRpdCBDYXJkfi0xLjE4NDQ2NzQ0MDc4MDA1NjVFMjB8ODAwMDExfkNoZWNraW5nfjEuOTk5OTk5ODQ0ODJFMTF8ODAwMDEzfkNoZWNraW5nfjQwMC4wfDgwMDAxNH5TYXZpbmdzfi00NDc1LjB8ODAwMDE1fklSQX41MDAwLjB8ODAwMDE2flNhdmluZ3N+MC4wfDgwMDAxN35TYXZpbmdzfjAuMHw4MDAwMTh+U2F2aW5nc34wLjB8ODAwMDE5flNhdmluZ3N+MC4wfDgwMDAyMH5TYXZpbmdzfjEuMDY2MDIwNjk2Njk3NzQ1OEUyMXw4MDAwMjF+Q2hlY2tpbmd+MTcwLjB8
authorization: Basic anNtaXRoOmRlbW8xMjM0


```

#### HTTP Response Evidence
```http
HTTP/1.1 200 (297.1ms)
server: Apache-Coyote/1.1
content-type: text/html;charset=ISO-8859-1
transfer-encoding: chunked
date: Fri, 09 Oct 2026 08:34:21 GMT







 
    

 

<!-- BEGIN HEADER -->
<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">

<html xmlns="http://www.w3.org/1999/xhtml" xml:lang="en" >



<head>
	<title>Altoro Mutual</title>
  <meta http-equiv="Content-Type" content="text/html; charset=iso-8859-1" />
  <link href="/style.css" rel="stylesheet" type="text/css" />
</head>
<body style="margin-top:5px;">

<div id="header" style="margin-bottom:5px; width: 99%;">
  <
```

#### Remediation
> Configure the web server or reverse proxy to strip or suppress the Server header.

---

### 45. [HIGH] Reflected Cross-Site Scripting (XSS) in Form Field 'query'

* **Detector Plugin:** `xss`
* **Evidence Type:** `screenshot`
* **Affected URL:** `GET http://demo.testfire.net/search.jsp` `[query]`

#### Description
Form field 'query' is vulnerable to reflected Cross-Site Scripting (XSS).

#### Technical Evidence
```text
Visual XSS confirmed. Injected payload '<script>document.body.style.backgroundColor='red';document.body.insertAdjacentHTML('afterbegin','<h1>dastXSS</h1>')</script>' executed in DOM with visual indicators.
```

#### Visual Screenshot Evidence
![Screenshot Evidence](C:\Users\HP\OneDrive\Desktop\SCANNER\evidence\screenshots\xss\step_012_xss_query_evidence_0ac6f8.png)
*File Path: `C:\Users\HP\OneDrive\Desktop\SCANNER\evidence\screenshots\xss\step_012_xss_query_evidence_0ac6f8.png`*

#### Remediation
> Contextually encode all user-supplied output (e.g. HTML entity encoding) and enforce a strict CSP.

---

### 46. [MEDIUM] Missing Clickjacking Defensive Framing Protections

* **Detector Plugin:** `clickjacking`
* **Evidence Type:** `http_traffic`
* **Affected URL:** `GET http://demo.testfire.net/logout.jsp`

#### Description
The page lacks both the X-Frame-Options header and CSP frame-ancestors directive. An attacker can frame this target within a transparent <iframe> on a malicious domain to trick authenticated users into clicking sensitive UI buttons (Clickjacking).

#### Technical Evidence
```text
HTTP Response Header Evidence:
X-Frame-Options Header: Missing
CSP frame-ancestors Directive: Missing
```

#### HTTP Request Evidence
```http
GET http://demo.testfire.net/index.jsp
host: demo.testfire.net
accept-encoding: gzip, deflate
connection: keep-alive
user-agent: DAST-Security-Auditor/1.0 (+authorized-security-assessment)
accept: */*
authorization: Basic anNtaXRoOmRlbW8xMjM0
cookie: JSESSIONID=4F0B4AB10DD4DD22B9B11DA8BDA795BC; AltoroAccounts=ODAwMDAyflNhdmluZ3N+LTguOTk5OTk3NDMyMDM3Nzc1RTI2fDgwMDAwM35DaGVja2luZ345LjAwMDAxNzc1MjQ1MTcwN0UyNnw0NTM5MDgyMDM5Mzk2Mjg4fkNyZWRpdCBDYXJkfi0xLjE4NDQ2NzQ0MDc4MDA1NjVFMjB8ODAwMDExfkNoZWNraW5nfjEuOTk5OTk5ODQ0ODJFMTF8ODAwMDEzfkNoZWNraW5nfjQwMC4wfDgwMDAxNH5TYXZpbmdzfi00NDc1LjB8ODAwMDE1fklSQX41MDAwLjB8ODAwMDE2flNhdmluZ3N+MC4wfDgwMDAxN35TYXZpbmdzfjAuMHw4MDAwMTh+U2F2aW5nc34wLjB8ODAwMDE5flNhdmluZ3N+MC4wfDgwMDAyMH5TYXZpbmdzfjEuMDY2MDIwNjk2Njk3NzQ1OEUyMXw4MDAwMjF+Q2hlY2tpbmd+MTcwLjB8


```

#### HTTP Response Evidence
```http
HTTP/1.1 200 (981.6ms)
server: Apache-Coyote/1.1
content-type: text/html;charset=ISO-8859-1
transfer-encoding: chunked
date: Fri, 09 Oct 2026 08:35:02 GMT







 
    

 

<!-- BEGIN HEADER -->
<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">

<html xmlns="http://www.w3.org/1999/xhtml" xml:lang="en" >



<head>
	<title>Altoro Mutual</title>
  <meta http-equiv="Content-Type" content="text/html; charset=iso-8859-1" />
  <link href="/style.css" rel="stylesheet" type="text/css" />
</head>
<body style="margin-top:5px;">

<div id="header" style="margin-bottom:5px; width: 99%;">
  <
```

#### Remediation
> Set 'X-Frame-Options: SAMEORIGIN' or 'Content-Security-Policy: frame-ancestors 'self''.

---

### 47. [MEDIUM] Missing Security Header: Content-Security-Policy

* **Detector Plugin:** `security_headers`
* **Evidence Type:** `http_traffic`
* **Affected URL:** `GET http://demo.testfire.net/logout.jsp`

#### Description
Protects against Cross-Site Scripting (XSS), data injection, and clickjacking attacks.

#### Technical Evidence
```text
HTTP Traffic Evidence:
Missing Recommended Security Header: Content-Security-Policy
Status Code: 200
Observed Headers: content-type, date, server, transfer-encoding
```

#### HTTP Request Evidence
```http
GET http://demo.testfire.net/index.jsp
host: demo.testfire.net
accept-encoding: gzip, deflate
connection: keep-alive
user-agent: DAST-Security-Auditor/1.0 (+authorized-security-assessment)
accept: */*
authorization: Basic anNtaXRoOmRlbW8xMjM0
cookie: JSESSIONID=4F0B4AB10DD4DD22B9B11DA8BDA795BC; AltoroAccounts=ODAwMDAyflNhdmluZ3N+LTguOTk5OTk3NDMyMDM3Nzc1RTI2fDgwMDAwM35DaGVja2luZ345LjAwMDAxNzc1MjQ1MTcwN0UyNnw0NTM5MDgyMDM5Mzk2Mjg4fkNyZWRpdCBDYXJkfi0xLjE4NDQ2NzQ0MDc4MDA1NjVFMjB8ODAwMDExfkNoZWNraW5nfjEuOTk5OTk5ODQ0ODJFMTF8ODAwMDEzfkNoZWNraW5nfjQwMC4wfDgwMDAxNH5TYXZpbmdzfi00NDc1LjB8ODAwMDE1fklSQX41MDAwLjB8ODAwMDE2flNhdmluZ3N+MC4wfDgwMDAxN35TYXZpbmdzfjAuMHw4MDAwMTh+U2F2aW5nc34wLjB8ODAwMDE5flNhdmluZ3N+MC4wfDgwMDAyMH5TYXZpbmdzfjEuMDY2MDIwNjk2Njk3NzQ1OEUyMXw4MDAwMjF+Q2hlY2tpbmd+MTcwLjB8


```

#### HTTP Response Evidence
```http
HTTP/1.1 200 (548.0ms)
server: Apache-Coyote/1.1
content-type: text/html;charset=ISO-8859-1
transfer-encoding: chunked
date: Fri, 09 Oct 2026 08:36:59 GMT







 
    

 

<!-- BEGIN HEADER -->
<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">

<html xmlns="http://www.w3.org/1999/xhtml" xml:lang="en" >



<head>
	<title>Altoro Mutual</title>
  <meta http-equiv="Content-Type" content="text/html; charset=iso-8859-1" />
  <link href="/style.css" rel="stylesheet" type="text/css" />
</head>
<body style="margin-top:5px;">

<div id="header" style="margin-bottom:5px; width: 99%;">
  <
```

#### Remediation
> Define and enforce a strict Content-Security-Policy (CSP) restricting trusted sources.

---

### 48. [MEDIUM] Missing Security Header: X-Frame-Options

* **Detector Plugin:** `security_headers`
* **Evidence Type:** `http_traffic`
* **Affected URL:** `GET http://demo.testfire.net/logout.jsp`

#### Description
Defends against UI redress attacks (Clickjacking) by disallowing framing.

#### Technical Evidence
```text
HTTP Traffic Evidence:
Missing Recommended Security Header: X-Frame-Options
Status Code: 200
Observed Headers: content-type, date, server, transfer-encoding
```

#### HTTP Request Evidence
```http
GET http://demo.testfire.net/index.jsp
host: demo.testfire.net
accept-encoding: gzip, deflate
connection: keep-alive
user-agent: DAST-Security-Auditor/1.0 (+authorized-security-assessment)
accept: */*
authorization: Basic anNtaXRoOmRlbW8xMjM0
cookie: JSESSIONID=4F0B4AB10DD4DD22B9B11DA8BDA795BC; AltoroAccounts=ODAwMDAyflNhdmluZ3N+LTguOTk5OTk3NDMyMDM3Nzc1RTI2fDgwMDAwM35DaGVja2luZ345LjAwMDAxNzc1MjQ1MTcwN0UyNnw0NTM5MDgyMDM5Mzk2Mjg4fkNyZWRpdCBDYXJkfi0xLjE4NDQ2NzQ0MDc4MDA1NjVFMjB8ODAwMDExfkNoZWNraW5nfjEuOTk5OTk5ODQ0ODJFMTF8ODAwMDEzfkNoZWNraW5nfjQwMC4wfDgwMDAxNH5TYXZpbmdzfi00NDc1LjB8ODAwMDE1fklSQX41MDAwLjB8ODAwMDE2flNhdmluZ3N+MC4wfDgwMDAxN35TYXZpbmdzfjAuMHw4MDAwMTh+U2F2aW5nc34wLjB8ODAwMDE5flNhdmluZ3N+MC4wfDgwMDAyMH5TYXZpbmdzfjEuMDY2MDIwNjk2Njk3NzQ1OEUyMXw4MDAwMjF+Q2hlY2tpbmd+MTcwLjB8


```

#### HTTP Response Evidence
```http
HTTP/1.1 200 (548.0ms)
server: Apache-Coyote/1.1
content-type: text/html;charset=ISO-8859-1
transfer-encoding: chunked
date: Fri, 09 Oct 2026 08:36:59 GMT







 
    

 

<!-- BEGIN HEADER -->
<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">

<html xmlns="http://www.w3.org/1999/xhtml" xml:lang="en" >



<head>
	<title>Altoro Mutual</title>
  <meta http-equiv="Content-Type" content="text/html; charset=iso-8859-1" />
  <link href="/style.css" rel="stylesheet" type="text/css" />
</head>
<body style="margin-top:5px;">

<div id="header" style="margin-bottom:5px; width: 99%;">
  <
```

#### Remediation
> Set X-Frame-Options to DENY or SAMEORIGIN.

---

### 49. [LOW] Missing Security Header: X-Content-Type-Options

* **Detector Plugin:** `security_headers`
* **Evidence Type:** `http_traffic`
* **Affected URL:** `GET http://demo.testfire.net/logout.jsp`

#### Description
Prevents MIME-type sniffing which can lead to script execution via non-executable files.

#### Technical Evidence
```text
HTTP Traffic Evidence:
Missing Recommended Security Header: X-Content-Type-Options
Status Code: 200
Observed Headers: content-type, date, server, transfer-encoding
```

#### HTTP Request Evidence
```http
GET http://demo.testfire.net/index.jsp
host: demo.testfire.net
accept-encoding: gzip, deflate
connection: keep-alive
user-agent: DAST-Security-Auditor/1.0 (+authorized-security-assessment)
accept: */*
authorization: Basic anNtaXRoOmRlbW8xMjM0
cookie: JSESSIONID=4F0B4AB10DD4DD22B9B11DA8BDA795BC; AltoroAccounts=ODAwMDAyflNhdmluZ3N+LTguOTk5OTk3NDMyMDM3Nzc1RTI2fDgwMDAwM35DaGVja2luZ345LjAwMDAxNzc1MjQ1MTcwN0UyNnw0NTM5MDgyMDM5Mzk2Mjg4fkNyZWRpdCBDYXJkfi0xLjE4NDQ2NzQ0MDc4MDA1NjVFMjB8ODAwMDExfkNoZWNraW5nfjEuOTk5OTk5ODQ0ODJFMTF8ODAwMDEzfkNoZWNraW5nfjQwMC4wfDgwMDAxNH5TYXZpbmdzfi00NDc1LjB8ODAwMDE1fklSQX41MDAwLjB8ODAwMDE2flNhdmluZ3N+MC4wfDgwMDAxN35TYXZpbmdzfjAuMHw4MDAwMTh+U2F2aW5nc34wLjB8ODAwMDE5flNhdmluZ3N+MC4wfDgwMDAyMH5TYXZpbmdzfjEuMDY2MDIwNjk2Njk3NzQ1OEUyMXw4MDAwMjF+Q2hlY2tpbmd+MTcwLjB8


```

#### HTTP Response Evidence
```http
HTTP/1.1 200 (548.0ms)
server: Apache-Coyote/1.1
content-type: text/html;charset=ISO-8859-1
transfer-encoding: chunked
date: Fri, 09 Oct 2026 08:36:59 GMT







 
    

 

<!-- BEGIN HEADER -->
<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">

<html xmlns="http://www.w3.org/1999/xhtml" xml:lang="en" >



<head>
	<title>Altoro Mutual</title>
  <meta http-equiv="Content-Type" content="text/html; charset=iso-8859-1" />
  <link href="/style.css" rel="stylesheet" type="text/css" />
</head>
<body style="margin-top:5px;">

<div id="header" style="margin-bottom:5px; width: 99%;">
  <
```

#### Remediation
> Set X-Content-Type-Options to 'nosniff'.

---

### 50. [LOW] Missing Security Header: Referrer-Policy

* **Detector Plugin:** `security_headers`
* **Evidence Type:** `http_traffic`
* **Affected URL:** `GET http://demo.testfire.net/logout.jsp`

#### Description
Protects sensitive URLs and query parameters from leaking via the HTTP Referer header.

#### Technical Evidence
```text
HTTP Traffic Evidence:
Missing Recommended Security Header: Referrer-Policy
Status Code: 200
Observed Headers: content-type, date, server, transfer-encoding
```

#### HTTP Request Evidence
```http
GET http://demo.testfire.net/index.jsp
host: demo.testfire.net
accept-encoding: gzip, deflate
connection: keep-alive
user-agent: DAST-Security-Auditor/1.0 (+authorized-security-assessment)
accept: */*
authorization: Basic anNtaXRoOmRlbW8xMjM0
cookie: JSESSIONID=4F0B4AB10DD4DD22B9B11DA8BDA795BC; AltoroAccounts=ODAwMDAyflNhdmluZ3N+LTguOTk5OTk3NDMyMDM3Nzc1RTI2fDgwMDAwM35DaGVja2luZ345LjAwMDAxNzc1MjQ1MTcwN0UyNnw0NTM5MDgyMDM5Mzk2Mjg4fkNyZWRpdCBDYXJkfi0xLjE4NDQ2NzQ0MDc4MDA1NjVFMjB8ODAwMDExfkNoZWNraW5nfjEuOTk5OTk5ODQ0ODJFMTF8ODAwMDEzfkNoZWNraW5nfjQwMC4wfDgwMDAxNH5TYXZpbmdzfi00NDc1LjB8ODAwMDE1fklSQX41MDAwLjB8ODAwMDE2flNhdmluZ3N+MC4wfDgwMDAxN35TYXZpbmdzfjAuMHw4MDAwMTh+U2F2aW5nc34wLjB8ODAwMDE5flNhdmluZ3N+MC4wfDgwMDAyMH5TYXZpbmdzfjEuMDY2MDIwNjk2Njk3NzQ1OEUyMXw4MDAwMjF+Q2hlY2tpbmd+MTcwLjB8


```

#### HTTP Response Evidence
```http
HTTP/1.1 200 (548.0ms)
server: Apache-Coyote/1.1
content-type: text/html;charset=ISO-8859-1
transfer-encoding: chunked
date: Fri, 09 Oct 2026 08:36:59 GMT







 
    

 

<!-- BEGIN HEADER -->
<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">

<html xmlns="http://www.w3.org/1999/xhtml" xml:lang="en" >



<head>
	<title>Altoro Mutual</title>
  <meta http-equiv="Content-Type" content="text/html; charset=iso-8859-1" />
  <link href="/style.css" rel="stylesheet" type="text/css" />
</head>
<body style="margin-top:5px;">

<div id="header" style="margin-bottom:5px; width: 99%;">
  <
```

#### Remediation
> Configure Referrer-Policy to 'strict-origin-when-cross-origin' or 'no-referrer'.

---

### 51. [LOW] Information Disclosure: Server Header

* **Detector Plugin:** `security_headers`
* **Evidence Type:** `http_traffic`
* **Affected URL:** `GET http://demo.testfire.net/logout.jsp`

#### Description
Web server vendor and version banner disclosure: 'Apache-Coyote/1.1' was returned in the server response.

#### Technical Evidence
```text
HTTP Traffic Evidence:
Disclosed Header: Server: Apache-Coyote/1.1
Status Code: 200
```

#### HTTP Request Evidence
```http
GET http://demo.testfire.net/index.jsp
host: demo.testfire.net
accept-encoding: gzip, deflate
connection: keep-alive
user-agent: DAST-Security-Auditor/1.0 (+authorized-security-assessment)
accept: */*
authorization: Basic anNtaXRoOmRlbW8xMjM0
cookie: JSESSIONID=4F0B4AB10DD4DD22B9B11DA8BDA795BC; AltoroAccounts=ODAwMDAyflNhdmluZ3N+LTguOTk5OTk3NDMyMDM3Nzc1RTI2fDgwMDAwM35DaGVja2luZ345LjAwMDAxNzc1MjQ1MTcwN0UyNnw0NTM5MDgyMDM5Mzk2Mjg4fkNyZWRpdCBDYXJkfi0xLjE4NDQ2NzQ0MDc4MDA1NjVFMjB8ODAwMDExfkNoZWNraW5nfjEuOTk5OTk5ODQ0ODJFMTF8ODAwMDEzfkNoZWNraW5nfjQwMC4wfDgwMDAxNH5TYXZpbmdzfi00NDc1LjB8ODAwMDE1fklSQX41MDAwLjB8ODAwMDE2flNhdmluZ3N+MC4wfDgwMDAxN35TYXZpbmdzfjAuMHw4MDAwMTh+U2F2aW5nc34wLjB8ODAwMDE5flNhdmluZ3N+MC4wfDgwMDAyMH5TYXZpbmdzfjEuMDY2MDIwNjk2Njk3NzQ1OEUyMXw4MDAwMjF+Q2hlY2tpbmd+MTcwLjB8


```

#### HTTP Response Evidence
```http
HTTP/1.1 200 (548.0ms)
server: Apache-Coyote/1.1
content-type: text/html;charset=ISO-8859-1
transfer-encoding: chunked
date: Fri, 09 Oct 2026 08:36:59 GMT







 
    

 

<!-- BEGIN HEADER -->
<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">

<html xmlns="http://www.w3.org/1999/xhtml" xml:lang="en" >



<head>
	<title>Altoro Mutual</title>
  <meta http-equiv="Content-Type" content="text/html; charset=iso-8859-1" />
  <link href="/style.css" rel="stylesheet" type="text/css" />
</head>
<body style="margin-top:5px;">

<div id="header" style="margin-bottom:5px; width: 99%;">
  <
```

#### Remediation
> Configure the web server or reverse proxy to strip or suppress the Server header.

---

### 52. [HIGH] Reflected Cross-Site Scripting (XSS) in Form Field 'query'

* **Detector Plugin:** `xss`
* **Evidence Type:** `screenshot`
* **Affected URL:** `GET http://demo.testfire.net/search.jsp` `[query]`

#### Description
Form field 'query' is vulnerable to reflected Cross-Site Scripting (XSS).

#### Technical Evidence
```text
Visual XSS confirmed. Injected payload '<script>document.body.style.backgroundColor='red';document.body.insertAdjacentHTML('afterbegin','<h1>dastXSS</h1>')</script>' executed in DOM with visual indicators.
```

#### Visual Screenshot Evidence
![Screenshot Evidence](C:\Users\HP\OneDrive\Desktop\SCANNER\evidence\screenshots\xss\step_013_xss_query_evidence_6088cf.png)
*File Path: `C:\Users\HP\OneDrive\Desktop\SCANNER\evidence\screenshots\xss\step_013_xss_query_evidence_6088cf.png`*

#### Remediation
> Contextually encode all user-supplied output (e.g. HTML entity encoding) and enforce a strict CSP.

---

### 53. [MEDIUM] Missing Clickjacking Defensive Framing Protections

* **Detector Plugin:** `clickjacking`
* **Evidence Type:** `http_traffic`
* **Affected URL:** `GET http://demo.testfire.net/index.jsp`

#### Description
The page lacks both the X-Frame-Options header and CSP frame-ancestors directive. An attacker can frame this target within a transparent <iframe> on a malicious domain to trick authenticated users into clicking sensitive UI buttons (Clickjacking).

#### Technical Evidence
```text
HTTP Response Header Evidence:
X-Frame-Options Header: Missing
CSP frame-ancestors Directive: Missing
```

#### HTTP Request Evidence
```http
GET http://demo.testfire.net/index.jsp
host: demo.testfire.net
accept-encoding: gzip, deflate
connection: keep-alive
user-agent: DAST-Security-Auditor/1.0 (+authorized-security-assessment)
accept: */*
cookie: JSESSIONID=4F0B4AB10DD4DD22B9B11DA8BDA795BC; AltoroAccounts=ODAwMDAyflNhdmluZ3N+LTguOTk5OTk3NDMyMDM3Nzc1RTI2fDgwMDAwM35DaGVja2luZ345LjAwMDAxNzc1MjQ1MTcwN0UyNnw0NTM5MDgyMDM5Mzk2Mjg4fkNyZWRpdCBDYXJkfi0xLjE4NDQ2NzQ0MDc4MDA1NjVFMjB8ODAwMDExfkNoZWNraW5nfjEuOTk5OTk5ODQ0ODJFMTF8ODAwMDEzfkNoZWNraW5nfjQwMC4wfDgwMDAxNH5TYXZpbmdzfi00NDc1LjB8ODAwMDE1fklSQX41MDAwLjB8ODAwMDE2flNhdmluZ3N+MC4wfDgwMDAxN35TYXZpbmdzfjAuMHw4MDAwMTh+U2F2aW5nc34wLjB8ODAwMDE5flNhdmluZ3N+MC4wfDgwMDAyMH5TYXZpbmdzfjEuMDY2MDIwNjk2Njk3NzQ1OEUyMXw4MDAwMjF+Q2hlY2tpbmd+MTcwLjB8
authorization: Basic anNtaXRoOmRlbW8xMjM0


```

#### HTTP Response Evidence
```http
HTTP/1.1 200 (297.0ms)
server: Apache-Coyote/1.1
content-type: text/html;charset=ISO-8859-1
transfer-encoding: chunked
date: Fri, 09 Oct 2026 08:37:34 GMT







 
    

 

<!-- BEGIN HEADER -->
<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">

<html xmlns="http://www.w3.org/1999/xhtml" xml:lang="en" >



<head>
	<title>Altoro Mutual</title>
  <meta http-equiv="Content-Type" content="text/html; charset=iso-8859-1" />
  <link href="/style.css" rel="stylesheet" type="text/css" />
</head>
<body style="margin-top:5px;">

<div id="header" style="margin-bottom:5px; width: 99%;">
  <
```

#### Remediation
> Set 'X-Frame-Options: SAMEORIGIN' or 'Content-Security-Policy: frame-ancestors 'self''.

---

### 54. [MEDIUM] HTML Injection in Parameter 'content'

* **Detector Plugin:** `html_injection`
* **Evidence Type:** `dom_evidence`
* **Affected URL:** `GET http://demo.testfire.net/index.jsp` `[content]`

#### Description
Parameter 'content' reflects user-supplied HTML tags directly into the web page without proper HTML entity encoding, allowing attackers to modify visual layout, deface pages, or perform phishing.

#### Technical Evidence
```text
DOM / HTML Traffic Evidence:
Injected HTML Payload: <h1>HTML_INJ_TEST</h1>
Unencoded Reflection: Matched rendered markup '<h1>HTML_INJ_TEST</h1>'
Technique: Heading tag injection
```

#### HTTP Request Evidence
```http
GET http://demo.testfire.net/index.jsp?content=%3Ch1%3EHTML_INJ_TEST%3C%2Fh1%3E
host: demo.testfire.net
accept-encoding: gzip, deflate
connection: keep-alive
user-agent: DAST-Security-Auditor/1.0 (+authorized-security-assessment)
accept: */*
cookie: JSESSIONID=4F0B4AB10DD4DD22B9B11DA8BDA795BC; AltoroAccounts=ODAwMDAyflNhdmluZ3N+LTguOTk5OTk3NDMyMDM3Nzc1RTI2fDgwMDAwM35DaGVja2luZ345LjAwMDAxNzc1MjQ1MTcwN0UyNnw0NTM5MDgyMDM5Mzk2Mjg4fkNyZWRpdCBDYXJkfi0xLjE4NDQ2NzQ0MDc4MDA1NjVFMjB8ODAwMDExfkNoZWNraW5nfjEuOTk5OTk5ODQ0ODJFMTF8ODAwMDEzfkNoZWNraW5nfjQwMC4wfDgwMDAxNH5TYXZpbmdzfi00NDc1LjB8ODAwMDE1fklSQX41MDAwLjB8ODAwMDE2flNhdmluZ3N+MC4wfDgwMDAxN35TYXZpbmdzfjAuMHw4MDAwMTh+U2F2aW5nc34wLjB8ODAwMDE5flNhdmluZ3N+MC4wfDgwMDAyMH5TYXZpbmdzfjEuMDY2MDIwNjk2Njk3NzQ1OEUyMXw4MDAwMjF+Q2hlY2tpbmd+MTcwLjB8
authorization: Basic anNtaXRoOmRlbW8xMjM0


```

#### HTTP Response Evidence
```http
HTTP/1.1 200 (306.1ms)
server: Apache-Coyote/1.1
content-type: text/html;charset=ISO-8859-1
content-length: 6820
date: Fri, 09 Oct 2026 08:38:33 GMT







 
    

 

<!-- BEGIN HEADER -->
<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">

<html xmlns="http://www.w3.org/1999/xhtml" xml:lang="en" >



<head>
	<title>Altoro Mutual</title>
  <meta http-equiv="Content-Type" content="text/html; charset=iso-8859-1" />
  <link href="/style.css" rel="stylesheet" type="text/css" />
</head>
<body style="margin-top:5px;">

<div id="header" style="margin-bottom:5px; width: 99%;">
  <
```

#### Remediation
> Contextually HTML entity encode all untrusted inputs before rendering them in the document.

---

### 55. [MEDIUM] Missing Security Header: Content-Security-Policy

* **Detector Plugin:** `security_headers`
* **Evidence Type:** `http_traffic`
* **Affected URL:** `GET http://demo.testfire.net/index.jsp`

#### Description
Protects against Cross-Site Scripting (XSS), data injection, and clickjacking attacks.

#### Technical Evidence
```text
HTTP Traffic Evidence:
Missing Recommended Security Header: Content-Security-Policy
Status Code: 200
Observed Headers: content-type, date, server, transfer-encoding
```

#### HTTP Request Evidence
```http
GET http://demo.testfire.net/index.jsp
host: demo.testfire.net
accept-encoding: gzip, deflate
connection: keep-alive
user-agent: DAST-Security-Auditor/1.0 (+authorized-security-assessment)
accept: */*
cookie: JSESSIONID=4F0B4AB10DD4DD22B9B11DA8BDA795BC; AltoroAccounts=ODAwMDAyflNhdmluZ3N+LTguOTk5OTk3NDMyMDM3Nzc1RTI2fDgwMDAwM35DaGVja2luZ345LjAwMDAxNzc1MjQ1MTcwN0UyNnw0NTM5MDgyMDM5Mzk2Mjg4fkNyZWRpdCBDYXJkfi0xLjE4NDQ2NzQ0MDc4MDA1NjVFMjB8ODAwMDExfkNoZWNraW5nfjEuOTk5OTk5ODQ0ODJFMTF8ODAwMDEzfkNoZWNraW5nfjQwMC4wfDgwMDAxNH5TYXZpbmdzfi00NDc1LjB8ODAwMDE1fklSQX41MDAwLjB8ODAwMDE2flNhdmluZ3N+MC4wfDgwMDAxN35TYXZpbmdzfjAuMHw4MDAwMTh+U2F2aW5nc34wLjB8ODAwMDE5flNhdmluZ3N+MC4wfDgwMDAyMH5TYXZpbmdzfjEuMDY2MDIwNjk2Njk3NzQ1OEUyMXw4MDAwMjF+Q2hlY2tpbmd+MTcwLjB8
authorization: Basic anNtaXRoOmRlbW8xMjM0


```

#### HTTP Response Evidence
```http
HTTP/1.1 200 (296.6ms)
server: Apache-Coyote/1.1
content-type: text/html;charset=ISO-8859-1
transfer-encoding: chunked
date: Fri, 09 Oct 2026 08:38:37 GMT







 
    

 

<!-- BEGIN HEADER -->
<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">

<html xmlns="http://www.w3.org/1999/xhtml" xml:lang="en" >



<head>
	<title>Altoro Mutual</title>
  <meta http-equiv="Content-Type" content="text/html; charset=iso-8859-1" />
  <link href="/style.css" rel="stylesheet" type="text/css" />
</head>
<body style="margin-top:5px;">

<div id="header" style="margin-bottom:5px; width: 99%;">
  <
```

#### Remediation
> Define and enforce a strict Content-Security-Policy (CSP) restricting trusted sources.

---

### 56. [MEDIUM] Missing Security Header: X-Frame-Options

* **Detector Plugin:** `security_headers`
* **Evidence Type:** `http_traffic`
* **Affected URL:** `GET http://demo.testfire.net/index.jsp`

#### Description
Defends against UI redress attacks (Clickjacking) by disallowing framing.

#### Technical Evidence
```text
HTTP Traffic Evidence:
Missing Recommended Security Header: X-Frame-Options
Status Code: 200
Observed Headers: content-type, date, server, transfer-encoding
```

#### HTTP Request Evidence
```http
GET http://demo.testfire.net/index.jsp
host: demo.testfire.net
accept-encoding: gzip, deflate
connection: keep-alive
user-agent: DAST-Security-Auditor/1.0 (+authorized-security-assessment)
accept: */*
cookie: JSESSIONID=4F0B4AB10DD4DD22B9B11DA8BDA795BC; AltoroAccounts=ODAwMDAyflNhdmluZ3N+LTguOTk5OTk3NDMyMDM3Nzc1RTI2fDgwMDAwM35DaGVja2luZ345LjAwMDAxNzc1MjQ1MTcwN0UyNnw0NTM5MDgyMDM5Mzk2Mjg4fkNyZWRpdCBDYXJkfi0xLjE4NDQ2NzQ0MDc4MDA1NjVFMjB8ODAwMDExfkNoZWNraW5nfjEuOTk5OTk5ODQ0ODJFMTF8ODAwMDEzfkNoZWNraW5nfjQwMC4wfDgwMDAxNH5TYXZpbmdzfi00NDc1LjB8ODAwMDE1fklSQX41MDAwLjB8ODAwMDE2flNhdmluZ3N+MC4wfDgwMDAxN35TYXZpbmdzfjAuMHw4MDAwMTh+U2F2aW5nc34wLjB8ODAwMDE5flNhdmluZ3N+MC4wfDgwMDAyMH5TYXZpbmdzfjEuMDY2MDIwNjk2Njk3NzQ1OEUyMXw4MDAwMjF+Q2hlY2tpbmd+MTcwLjB8
authorization: Basic anNtaXRoOmRlbW8xMjM0


```

#### HTTP Response Evidence
```http
HTTP/1.1 200 (296.6ms)
server: Apache-Coyote/1.1
content-type: text/html;charset=ISO-8859-1
transfer-encoding: chunked
date: Fri, 09 Oct 2026 08:38:37 GMT







 
    

 

<!-- BEGIN HEADER -->
<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">

<html xmlns="http://www.w3.org/1999/xhtml" xml:lang="en" >



<head>
	<title>Altoro Mutual</title>
  <meta http-equiv="Content-Type" content="text/html; charset=iso-8859-1" />
  <link href="/style.css" rel="stylesheet" type="text/css" />
</head>
<body style="margin-top:5px;">

<div id="header" style="margin-bottom:5px; width: 99%;">
  <
```

#### Remediation
> Set X-Frame-Options to DENY or SAMEORIGIN.

---

### 57. [LOW] Missing Security Header: X-Content-Type-Options

* **Detector Plugin:** `security_headers`
* **Evidence Type:** `http_traffic`
* **Affected URL:** `GET http://demo.testfire.net/index.jsp`

#### Description
Prevents MIME-type sniffing which can lead to script execution via non-executable files.

#### Technical Evidence
```text
HTTP Traffic Evidence:
Missing Recommended Security Header: X-Content-Type-Options
Status Code: 200
Observed Headers: content-type, date, server, transfer-encoding
```

#### HTTP Request Evidence
```http
GET http://demo.testfire.net/index.jsp
host: demo.testfire.net
accept-encoding: gzip, deflate
connection: keep-alive
user-agent: DAST-Security-Auditor/1.0 (+authorized-security-assessment)
accept: */*
cookie: JSESSIONID=4F0B4AB10DD4DD22B9B11DA8BDA795BC; AltoroAccounts=ODAwMDAyflNhdmluZ3N+LTguOTk5OTk3NDMyMDM3Nzc1RTI2fDgwMDAwM35DaGVja2luZ345LjAwMDAxNzc1MjQ1MTcwN0UyNnw0NTM5MDgyMDM5Mzk2Mjg4fkNyZWRpdCBDYXJkfi0xLjE4NDQ2NzQ0MDc4MDA1NjVFMjB8ODAwMDExfkNoZWNraW5nfjEuOTk5OTk5ODQ0ODJFMTF8ODAwMDEzfkNoZWNraW5nfjQwMC4wfDgwMDAxNH5TYXZpbmdzfi00NDc1LjB8ODAwMDE1fklSQX41MDAwLjB8ODAwMDE2flNhdmluZ3N+MC4wfDgwMDAxN35TYXZpbmdzfjAuMHw4MDAwMTh+U2F2aW5nc34wLjB8ODAwMDE5flNhdmluZ3N+MC4wfDgwMDAyMH5TYXZpbmdzfjEuMDY2MDIwNjk2Njk3NzQ1OEUyMXw4MDAwMjF+Q2hlY2tpbmd+MTcwLjB8
authorization: Basic anNtaXRoOmRlbW8xMjM0


```

#### HTTP Response Evidence
```http
HTTP/1.1 200 (296.6ms)
server: Apache-Coyote/1.1
content-type: text/html;charset=ISO-8859-1
transfer-encoding: chunked
date: Fri, 09 Oct 2026 08:38:37 GMT







 
    

 

<!-- BEGIN HEADER -->
<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">

<html xmlns="http://www.w3.org/1999/xhtml" xml:lang="en" >



<head>
	<title>Altoro Mutual</title>
  <meta http-equiv="Content-Type" content="text/html; charset=iso-8859-1" />
  <link href="/style.css" rel="stylesheet" type="text/css" />
</head>
<body style="margin-top:5px;">

<div id="header" style="margin-bottom:5px; width: 99%;">
  <
```

#### Remediation
> Set X-Content-Type-Options to 'nosniff'.

---

### 58. [LOW] Missing Security Header: Referrer-Policy

* **Detector Plugin:** `security_headers`
* **Evidence Type:** `http_traffic`
* **Affected URL:** `GET http://demo.testfire.net/index.jsp`

#### Description
Protects sensitive URLs and query parameters from leaking via the HTTP Referer header.

#### Technical Evidence
```text
HTTP Traffic Evidence:
Missing Recommended Security Header: Referrer-Policy
Status Code: 200
Observed Headers: content-type, date, server, transfer-encoding
```

#### HTTP Request Evidence
```http
GET http://demo.testfire.net/index.jsp
host: demo.testfire.net
accept-encoding: gzip, deflate
connection: keep-alive
user-agent: DAST-Security-Auditor/1.0 (+authorized-security-assessment)
accept: */*
cookie: JSESSIONID=4F0B4AB10DD4DD22B9B11DA8BDA795BC; AltoroAccounts=ODAwMDAyflNhdmluZ3N+LTguOTk5OTk3NDMyMDM3Nzc1RTI2fDgwMDAwM35DaGVja2luZ345LjAwMDAxNzc1MjQ1MTcwN0UyNnw0NTM5MDgyMDM5Mzk2Mjg4fkNyZWRpdCBDYXJkfi0xLjE4NDQ2NzQ0MDc4MDA1NjVFMjB8ODAwMDExfkNoZWNraW5nfjEuOTk5OTk5ODQ0ODJFMTF8ODAwMDEzfkNoZWNraW5nfjQwMC4wfDgwMDAxNH5TYXZpbmdzfi00NDc1LjB8ODAwMDE1fklSQX41MDAwLjB8ODAwMDE2flNhdmluZ3N+MC4wfDgwMDAxN35TYXZpbmdzfjAuMHw4MDAwMTh+U2F2aW5nc34wLjB8ODAwMDE5flNhdmluZ3N+MC4wfDgwMDAyMH5TYXZpbmdzfjEuMDY2MDIwNjk2Njk3NzQ1OEUyMXw4MDAwMjF+Q2hlY2tpbmd+MTcwLjB8
authorization: Basic anNtaXRoOmRlbW8xMjM0


```

#### HTTP Response Evidence
```http
HTTP/1.1 200 (296.6ms)
server: Apache-Coyote/1.1
content-type: text/html;charset=ISO-8859-1
transfer-encoding: chunked
date: Fri, 09 Oct 2026 08:38:37 GMT







 
    

 

<!-- BEGIN HEADER -->
<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">

<html xmlns="http://www.w3.org/1999/xhtml" xml:lang="en" >



<head>
	<title>Altoro Mutual</title>
  <meta http-equiv="Content-Type" content="text/html; charset=iso-8859-1" />
  <link href="/style.css" rel="stylesheet" type="text/css" />
</head>
<body style="margin-top:5px;">

<div id="header" style="margin-bottom:5px; width: 99%;">
  <
```

#### Remediation
> Configure Referrer-Policy to 'strict-origin-when-cross-origin' or 'no-referrer'.

---

### 59. [LOW] Information Disclosure: Server Header

* **Detector Plugin:** `security_headers`
* **Evidence Type:** `http_traffic`
* **Affected URL:** `GET http://demo.testfire.net/index.jsp`

#### Description
Web server vendor and version banner disclosure: 'Apache-Coyote/1.1' was returned in the server response.

#### Technical Evidence
```text
HTTP Traffic Evidence:
Disclosed Header: Server: Apache-Coyote/1.1
Status Code: 200
```

#### HTTP Request Evidence
```http
GET http://demo.testfire.net/index.jsp
host: demo.testfire.net
accept-encoding: gzip, deflate
connection: keep-alive
user-agent: DAST-Security-Auditor/1.0 (+authorized-security-assessment)
accept: */*
cookie: JSESSIONID=4F0B4AB10DD4DD22B9B11DA8BDA795BC; AltoroAccounts=ODAwMDAyflNhdmluZ3N+LTguOTk5OTk3NDMyMDM3Nzc1RTI2fDgwMDAwM35DaGVja2luZ345LjAwMDAxNzc1MjQ1MTcwN0UyNnw0NTM5MDgyMDM5Mzk2Mjg4fkNyZWRpdCBDYXJkfi0xLjE4NDQ2NzQ0MDc4MDA1NjVFMjB8ODAwMDExfkNoZWNraW5nfjEuOTk5OTk5ODQ0ODJFMTF8ODAwMDEzfkNoZWNraW5nfjQwMC4wfDgwMDAxNH5TYXZpbmdzfi00NDc1LjB8ODAwMDE1fklSQX41MDAwLjB8ODAwMDE2flNhdmluZ3N+MC4wfDgwMDAxN35TYXZpbmdzfjAuMHw4MDAwMTh+U2F2aW5nc34wLjB8ODAwMDE5flNhdmluZ3N+MC4wfDgwMDAyMH5TYXZpbmdzfjEuMDY2MDIwNjk2Njk3NzQ1OEUyMXw4MDAwMjF+Q2hlY2tpbmd+MTcwLjB8
authorization: Basic anNtaXRoOmRlbW8xMjM0


```

#### HTTP Response Evidence
```http
HTTP/1.1 200 (296.6ms)
server: Apache-Coyote/1.1
content-type: text/html;charset=ISO-8859-1
transfer-encoding: chunked
date: Fri, 09 Oct 2026 08:38:37 GMT







 
    

 

<!-- BEGIN HEADER -->
<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">

<html xmlns="http://www.w3.org/1999/xhtml" xml:lang="en" >



<head>
	<title>Altoro Mutual</title>
  <meta http-equiv="Content-Type" content="text/html; charset=iso-8859-1" />
  <link href="/style.css" rel="stylesheet" type="text/css" />
</head>
<body style="margin-top:5px;">

<div id="header" style="margin-bottom:5px; width: 99%;">
  <
```

#### Remediation
> Configure the web server or reverse proxy to strip or suppress the Server header.

---

### 60. [HIGH] DOM-Based Cross-Site Scripting (DOM XSS) in 'content'

* **Detector Plugin:** `dom_xss`
* **Evidence Type:** `screenshot`
* **Affected URL:** `GET http://demo.testfire.net/index.jsp?content=";document.body.style.backgroundColor='red';document.body.insertAdjacentHTML('afterbegin','<h1>dastXSS</h1>');//` `[content]`

#### Description
Parameter or URL fragment flows into an unsafe client-side DOM sink without sanitization.

#### Technical Evidence
```text
Live DOM XSS confirmed in browser. Injected vector executed in client-side DOM sink.
Target URL: http://demo.testfire.net/index.jsp?content=";document.body.style.backgroundColor='red';document.body.insertAdjacentHTML('afterbegin','<h1>dastXSS</h1>');//
Payload: ";document.body.style.backgroundColor='red';document.body.insertAdjacentHTML('afterbegin','<h1>dastXSS</h1>');//
```

#### Visual Screenshot Evidence
![Screenshot Evidence](C:\Users\HP\OneDrive\Desktop\SCANNER\evidence\screenshots\dom_xss\step_014_dom_xss_content_evidence_efce14.png)
*File Path: `C:\Users\HP\OneDrive\Desktop\SCANNER\evidence\screenshots\dom_xss\step_014_dom_xss_content_evidence_efce14.png`*

#### Remediation
> Avoid passing untrusted URL parameters or location hashes to innerHTML/document.write. Use textContent or DOMPurify.

---

### 61. [HIGH] Reflected Cross-Site Scripting (XSS) in Form Field 'query'

* **Detector Plugin:** `xss`
* **Evidence Type:** `screenshot`
* **Affected URL:** `GET http://demo.testfire.net/search.jsp` `[query]`

#### Description
Form field 'query' is vulnerable to reflected Cross-Site Scripting (XSS).

#### Technical Evidence
```text
Visual XSS confirmed. Injected payload '<script>document.body.style.backgroundColor='red';document.body.insertAdjacentHTML('afterbegin','<h1>dastXSS</h1>')</script>' executed in DOM with visual indicators.
```

#### Visual Screenshot Evidence
![Screenshot Evidence](C:\Users\HP\OneDrive\Desktop\SCANNER\evidence\screenshots\xss\step_015_xss_query_evidence_99c12e.png)
*File Path: `C:\Users\HP\OneDrive\Desktop\SCANNER\evidence\screenshots\xss\step_015_xss_query_evidence_99c12e.png`*

#### Remediation
> Contextually encode all user-supplied output (e.g. HTML entity encoding) and enforce a strict CSP.

---

### 62. [MEDIUM] Missing Clickjacking Defensive Framing Protections

* **Detector Plugin:** `clickjacking`
* **Evidence Type:** `http_traffic`
* **Affected URL:** `POST http://demo.testfire.net/sendFeedback`

#### Description
The page lacks both the X-Frame-Options header and CSP frame-ancestors directive. An attacker can frame this target within a transparent <iframe> on a malicious domain to trick authenticated users into clicking sensitive UI buttons (Clickjacking).

#### Technical Evidence
```text
HTTP Response Header Evidence:
X-Frame-Options Header: Missing
CSP frame-ancestors Directive: Missing
```

#### HTTP Request Evidence
```http
GET http://demo.testfire.net/sendFeedback
host: demo.testfire.net
accept-encoding: gzip, deflate
connection: keep-alive
user-agent: DAST-Security-Auditor/1.0 (+authorized-security-assessment)
accept: */*
cookie: JSESSIONID=4F0B4AB10DD4DD22B9B11DA8BDA795BC; AltoroAccounts=ODAwMDAyflNhdmluZ3N+LTguOTk5OTk3NDMyMDM3Nzc1RTI2fDgwMDAwM35DaGVja2luZ345LjAwMDAxNzc1MjQ1MTcwN0UyNnw0NTM5MDgyMDM5Mzk2Mjg4fkNyZWRpdCBDYXJkfi0xLjE4NDQ2NzQ0MDc4MDA1NjVFMjB8ODAwMDExfkNoZWNraW5nfjEuOTk5OTk5ODQ0ODJFMTF8ODAwMDEzfkNoZWNraW5nfjQwMC4wfDgwMDAxNH5TYXZpbmdzfi00NDc1LjB8ODAwMDE1fklSQX41MDAwLjB8ODAwMDE2flNhdmluZ3N+MC4wfDgwMDAxN35TYXZpbmdzfjAuMHw4MDAwMTh+U2F2aW5nc34wLjB8ODAwMDE5flNhdmluZ3N+MC4wfDgwMDAyMH5TYXZpbmdzfjEuMDY2MDIwNjk2Njk3NzQ1OEUyMXw4MDAwMjF+Q2hlY2tpbmd+MTcwLjB8
authorization: Basic anNtaXRoOmRlbW8xMjM0


```

#### HTTP Response Evidence
```http
HTTP/1.1 405 (377.7ms)
server: Apache-Coyote/1.1
content-type: text/html;charset=utf-8
content-language: en
content-length: 1082
date: Fri, 09 Oct 2026 08:38:57 GMT

<!doctype html><html lang="en"><head><title>HTTP Status 405 – Method Not Allowed</title><style type="text/css">H1 {font-family:Tahoma,Arial,sans-serif;color:white;background-color:#525D76;font-size:22px;} H2 {font-family:Tahoma,Arial,sans-serif;color:white;background-color:#525D76;font-size:16px;} H3 {font-family:Tahoma,Arial,sans-serif;color:white;background-color:#525D76;font-size:14px;} BODY {font-family:Tahoma,Arial,sans-serif;color:black;background-color:white;} B {font-family:Tahoma,Arial,
```

#### Remediation
> Set 'X-Frame-Options: SAMEORIGIN' or 'Content-Security-Policy: frame-ancestors 'self''.

---

### 63. [MEDIUM] HTML Injection in Parameter 'email_addr'

* **Detector Plugin:** `html_injection`
* **Evidence Type:** `dom_evidence`
* **Affected URL:** `POST http://demo.testfire.net/sendFeedback` `[email_addr]`

#### Description
Parameter 'email_addr' reflects user-supplied HTML tags directly into the web page without proper HTML entity encoding, allowing attackers to modify visual layout, deface pages, or perform phishing.

#### Technical Evidence
```text
DOM / HTML Traffic Evidence:
Injected HTML Payload: <iframe src="about:blank" height="0" width="0"></iframe>
Unencoded Reflection: Matched rendered markup '<iframe src="about:blank"'
Technique: iFrame tag injection
```

#### HTTP Request Evidence
```http
POST http://demo.testfire.net/sendFeedback
host: demo.testfire.net
accept-encoding: gzip, deflate
connection: keep-alive
user-agent: DAST-Security-Auditor/1.0 (+authorized-security-assessment)
accept: */*
cookie: JSESSIONID=4F0B4AB10DD4DD22B9B11DA8BDA795BC; AltoroAccounts=ODAwMDAyflNhdmluZ3N+LTguOTk5OTk3NDMyMDM3Nzc1RTI2fDgwMDAwM35DaGVja2luZ345LjAwMDAxNzc1MjQ1MTcwN0UyNnw0NTM5MDgyMDM5Mzk2Mjg4fkNyZWRpdCBDYXJkfi0xLjE4NDQ2NzQ0MDc4MDA1NjVFMjB8ODAwMDExfkNoZWNraW5nfjEuOTk5OTk5ODQ0ODJFMTF8ODAwMDEzfkNoZWNraW5nfjQwMC4wfDgwMDAxNH5TYXZpbmdzfi00NDc1LjB8ODAwMDE1fklSQX41MDAwLjB8ODAwMDE2flNhdmluZ3N+MC4wfDgwMDAxN35TYXZpbmdzfjAuMHw4MDAwMTh+U2F2aW5nc34wLjB8ODAwMDE5flNhdmluZ3N+MC4wfDgwMDAyMH5TYXZpbmdzfjEuMDY2MDIwNjk2Njk3NzQ1OEUyMXw4MDAwMjF+Q2hlY2tpbmd+MTcwLjB8
content-length: 184
content-type: application/x-www-form-urlencoded
authorization: Basic anNtaXRoOmRlbW8xMjM0

{'cfile': 'comments.txt', 'name': '', 'email_addr': '<iframe src="about:blank" height="0" width="0"></iframe>', 'subject': 'test', 'comments': 'test', 'submit': ' Submit ', 'reset': ' Clear Form '}
```

#### HTTP Response Evidence
```http
HTTP/1.1 200 (296.2ms)
server: Apache-Coyote/1.1
content-type: text/html;charset=ISO-8859-1
content-length: 7097
date: Fri, 09 Oct 2026 08:40:23 GMT





 

    
    



 

<!-- BEGIN HEADER -->
<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">

<html xmlns="http://www.w3.org/1999/xhtml" xml:lang="en" >



<head>
	<title>Altoro Mutual</title>
  <meta http-equiv="Content-Type" content="text/html; charset=iso-8859-1" />
  <link href="/style.css" rel="stylesheet" type="text/css" />
</head>
<body style="margin-top:5px;">

<div id="header" style="margin-bottom:5px; width: 99%;
```

#### Remediation
> Contextually HTML entity encode all untrusted inputs before rendering them in the document.

---

### 64. [MEDIUM] Missing Security Header: Content-Security-Policy

* **Detector Plugin:** `security_headers`
* **Evidence Type:** `http_traffic`
* **Affected URL:** `POST http://demo.testfire.net/sendFeedback`

#### Description
Protects against Cross-Site Scripting (XSS), data injection, and clickjacking attacks.

#### Technical Evidence
```text
HTTP Traffic Evidence:
Missing Recommended Security Header: Content-Security-Policy
Status Code: 405
Observed Headers: connection, content-language, content-length, content-type, date, server
```

#### HTTP Request Evidence
```http
GET http://demo.testfire.net/sendFeedback
host: demo.testfire.net
accept-encoding: gzip, deflate
connection: keep-alive
user-agent: DAST-Security-Auditor/1.0 (+authorized-security-assessment)
accept: */*
cookie: JSESSIONID=4F0B4AB10DD4DD22B9B11DA8BDA795BC; AltoroAccounts=ODAwMDAyflNhdmluZ3N+LTguOTk5OTk3NDMyMDM3Nzc1RTI2fDgwMDAwM35DaGVja2luZ345LjAwMDAxNzc1MjQ1MTcwN0UyNnw0NTM5MDgyMDM5Mzk2Mjg4fkNyZWRpdCBDYXJkfi0xLjE4NDQ2NzQ0MDc4MDA1NjVFMjB8ODAwMDExfkNoZWNraW5nfjEuOTk5OTk5ODQ0ODJFMTF8ODAwMDEzfkNoZWNraW5nfjQwMC4wfDgwMDAxNH5TYXZpbmdzfi00NDc1LjB8ODAwMDE1fklSQX41MDAwLjB8ODAwMDE2flNhdmluZ3N+MC4wfDgwMDAxN35TYXZpbmdzfjAuMHw4MDAwMTh+U2F2aW5nc34wLjB8ODAwMDE5flNhdmluZ3N+MC4wfDgwMDAyMH5TYXZpbmdzfjEuMDY2MDIwNjk2Njk3NzQ1OEUyMXw4MDAwMjF+Q2hlY2tpbmd+MTcwLjB8
authorization: Basic anNtaXRoOmRlbW8xMjM0


```

#### HTTP Response Evidence
```http
HTTP/1.1 405 (3599.9ms)
server: Apache-Coyote/1.1
content-type: text/html;charset=utf-8
content-language: en
content-length: 1082
date: Fri, 09 Oct 2026 08:40:33 GMT
connection: close

<!doctype html><html lang="en"><head><title>HTTP Status 405 – Method Not Allowed</title><style type="text/css">H1 {font-family:Tahoma,Arial,sans-serif;color:white;background-color:#525D76;font-size:22px;} H2 {font-family:Tahoma,Arial,sans-serif;color:white;background-color:#525D76;font-size:16px;} H3 {font-family:Tahoma,Arial,sans-serif;color:white;background-color:#525D76;font-size:14px;} BODY {font-family:Tahoma,Arial,sans-serif;color:black;background-color:white;} B {font-family:Tahoma,Arial,
```

#### Remediation
> Define and enforce a strict Content-Security-Policy (CSP) restricting trusted sources.

---

### 65. [MEDIUM] Missing Security Header: X-Frame-Options

* **Detector Plugin:** `security_headers`
* **Evidence Type:** `http_traffic`
* **Affected URL:** `POST http://demo.testfire.net/sendFeedback`

#### Description
Defends against UI redress attacks (Clickjacking) by disallowing framing.

#### Technical Evidence
```text
HTTP Traffic Evidence:
Missing Recommended Security Header: X-Frame-Options
Status Code: 405
Observed Headers: connection, content-language, content-length, content-type, date, server
```

#### HTTP Request Evidence
```http
GET http://demo.testfire.net/sendFeedback
host: demo.testfire.net
accept-encoding: gzip, deflate
connection: keep-alive
user-agent: DAST-Security-Auditor/1.0 (+authorized-security-assessment)
accept: */*
cookie: JSESSIONID=4F0B4AB10DD4DD22B9B11DA8BDA795BC; AltoroAccounts=ODAwMDAyflNhdmluZ3N+LTguOTk5OTk3NDMyMDM3Nzc1RTI2fDgwMDAwM35DaGVja2luZ345LjAwMDAxNzc1MjQ1MTcwN0UyNnw0NTM5MDgyMDM5Mzk2Mjg4fkNyZWRpdCBDYXJkfi0xLjE4NDQ2NzQ0MDc4MDA1NjVFMjB8ODAwMDExfkNoZWNraW5nfjEuOTk5OTk5ODQ0ODJFMTF8ODAwMDEzfkNoZWNraW5nfjQwMC4wfDgwMDAxNH5TYXZpbmdzfi00NDc1LjB8ODAwMDE1fklSQX41MDAwLjB8ODAwMDE2flNhdmluZ3N+MC4wfDgwMDAxN35TYXZpbmdzfjAuMHw4MDAwMTh+U2F2aW5nc34wLjB8ODAwMDE5flNhdmluZ3N+MC4wfDgwMDAyMH5TYXZpbmdzfjEuMDY2MDIwNjk2Njk3NzQ1OEUyMXw4MDAwMjF+Q2hlY2tpbmd+MTcwLjB8
authorization: Basic anNtaXRoOmRlbW8xMjM0


```

#### HTTP Response Evidence
```http
HTTP/1.1 405 (3599.9ms)
server: Apache-Coyote/1.1
content-type: text/html;charset=utf-8
content-language: en
content-length: 1082
date: Fri, 09 Oct 2026 08:40:33 GMT
connection: close

<!doctype html><html lang="en"><head><title>HTTP Status 405 – Method Not Allowed</title><style type="text/css">H1 {font-family:Tahoma,Arial,sans-serif;color:white;background-color:#525D76;font-size:22px;} H2 {font-family:Tahoma,Arial,sans-serif;color:white;background-color:#525D76;font-size:16px;} H3 {font-family:Tahoma,Arial,sans-serif;color:white;background-color:#525D76;font-size:14px;} BODY {font-family:Tahoma,Arial,sans-serif;color:black;background-color:white;} B {font-family:Tahoma,Arial,
```

#### Remediation
> Set X-Frame-Options to DENY or SAMEORIGIN.

---

### 66. [LOW] Missing Security Header: X-Content-Type-Options

* **Detector Plugin:** `security_headers`
* **Evidence Type:** `http_traffic`
* **Affected URL:** `POST http://demo.testfire.net/sendFeedback`

#### Description
Prevents MIME-type sniffing which can lead to script execution via non-executable files.

#### Technical Evidence
```text
HTTP Traffic Evidence:
Missing Recommended Security Header: X-Content-Type-Options
Status Code: 405
Observed Headers: connection, content-language, content-length, content-type, date, server
```

#### HTTP Request Evidence
```http
GET http://demo.testfire.net/sendFeedback
host: demo.testfire.net
accept-encoding: gzip, deflate
connection: keep-alive
user-agent: DAST-Security-Auditor/1.0 (+authorized-security-assessment)
accept: */*
cookie: JSESSIONID=4F0B4AB10DD4DD22B9B11DA8BDA795BC; AltoroAccounts=ODAwMDAyflNhdmluZ3N+LTguOTk5OTk3NDMyMDM3Nzc1RTI2fDgwMDAwM35DaGVja2luZ345LjAwMDAxNzc1MjQ1MTcwN0UyNnw0NTM5MDgyMDM5Mzk2Mjg4fkNyZWRpdCBDYXJkfi0xLjE4NDQ2NzQ0MDc4MDA1NjVFMjB8ODAwMDExfkNoZWNraW5nfjEuOTk5OTk5ODQ0ODJFMTF8ODAwMDEzfkNoZWNraW5nfjQwMC4wfDgwMDAxNH5TYXZpbmdzfi00NDc1LjB8ODAwMDE1fklSQX41MDAwLjB8ODAwMDE2flNhdmluZ3N+MC4wfDgwMDAxN35TYXZpbmdzfjAuMHw4MDAwMTh+U2F2aW5nc34wLjB8ODAwMDE5flNhdmluZ3N+MC4wfDgwMDAyMH5TYXZpbmdzfjEuMDY2MDIwNjk2Njk3NzQ1OEUyMXw4MDAwMjF+Q2hlY2tpbmd+MTcwLjB8
authorization: Basic anNtaXRoOmRlbW8xMjM0


```

#### HTTP Response Evidence
```http
HTTP/1.1 405 (3599.9ms)
server: Apache-Coyote/1.1
content-type: text/html;charset=utf-8
content-language: en
content-length: 1082
date: Fri, 09 Oct 2026 08:40:33 GMT
connection: close

<!doctype html><html lang="en"><head><title>HTTP Status 405 – Method Not Allowed</title><style type="text/css">H1 {font-family:Tahoma,Arial,sans-serif;color:white;background-color:#525D76;font-size:22px;} H2 {font-family:Tahoma,Arial,sans-serif;color:white;background-color:#525D76;font-size:16px;} H3 {font-family:Tahoma,Arial,sans-serif;color:white;background-color:#525D76;font-size:14px;} BODY {font-family:Tahoma,Arial,sans-serif;color:black;background-color:white;} B {font-family:Tahoma,Arial,
```

#### Remediation
> Set X-Content-Type-Options to 'nosniff'.

---

### 67. [LOW] Missing Security Header: Referrer-Policy

* **Detector Plugin:** `security_headers`
* **Evidence Type:** `http_traffic`
* **Affected URL:** `POST http://demo.testfire.net/sendFeedback`

#### Description
Protects sensitive URLs and query parameters from leaking via the HTTP Referer header.

#### Technical Evidence
```text
HTTP Traffic Evidence:
Missing Recommended Security Header: Referrer-Policy
Status Code: 405
Observed Headers: connection, content-language, content-length, content-type, date, server
```

#### HTTP Request Evidence
```http
GET http://demo.testfire.net/sendFeedback
host: demo.testfire.net
accept-encoding: gzip, deflate
connection: keep-alive
user-agent: DAST-Security-Auditor/1.0 (+authorized-security-assessment)
accept: */*
cookie: JSESSIONID=4F0B4AB10DD4DD22B9B11DA8BDA795BC; AltoroAccounts=ODAwMDAyflNhdmluZ3N+LTguOTk5OTk3NDMyMDM3Nzc1RTI2fDgwMDAwM35DaGVja2luZ345LjAwMDAxNzc1MjQ1MTcwN0UyNnw0NTM5MDgyMDM5Mzk2Mjg4fkNyZWRpdCBDYXJkfi0xLjE4NDQ2NzQ0MDc4MDA1NjVFMjB8ODAwMDExfkNoZWNraW5nfjEuOTk5OTk5ODQ0ODJFMTF8ODAwMDEzfkNoZWNraW5nfjQwMC4wfDgwMDAxNH5TYXZpbmdzfi00NDc1LjB8ODAwMDE1fklSQX41MDAwLjB8ODAwMDE2flNhdmluZ3N+MC4wfDgwMDAxN35TYXZpbmdzfjAuMHw4MDAwMTh+U2F2aW5nc34wLjB8ODAwMDE5flNhdmluZ3N+MC4wfDgwMDAyMH5TYXZpbmdzfjEuMDY2MDIwNjk2Njk3NzQ1OEUyMXw4MDAwMjF+Q2hlY2tpbmd+MTcwLjB8
authorization: Basic anNtaXRoOmRlbW8xMjM0


```

#### HTTP Response Evidence
```http
HTTP/1.1 405 (3599.9ms)
server: Apache-Coyote/1.1
content-type: text/html;charset=utf-8
content-language: en
content-length: 1082
date: Fri, 09 Oct 2026 08:40:33 GMT
connection: close

<!doctype html><html lang="en"><head><title>HTTP Status 405 – Method Not Allowed</title><style type="text/css">H1 {font-family:Tahoma,Arial,sans-serif;color:white;background-color:#525D76;font-size:22px;} H2 {font-family:Tahoma,Arial,sans-serif;color:white;background-color:#525D76;font-size:16px;} H3 {font-family:Tahoma,Arial,sans-serif;color:white;background-color:#525D76;font-size:14px;} BODY {font-family:Tahoma,Arial,sans-serif;color:black;background-color:white;} B {font-family:Tahoma,Arial,
```

#### Remediation
> Configure Referrer-Policy to 'strict-origin-when-cross-origin' or 'no-referrer'.

---

### 68. [LOW] Information Disclosure: Server Header

* **Detector Plugin:** `security_headers`
* **Evidence Type:** `http_traffic`
* **Affected URL:** `POST http://demo.testfire.net/sendFeedback`

#### Description
Web server vendor and version banner disclosure: 'Apache-Coyote/1.1' was returned in the server response.

#### Technical Evidence
```text
HTTP Traffic Evidence:
Disclosed Header: Server: Apache-Coyote/1.1
Status Code: 405
```

#### HTTP Request Evidence
```http
GET http://demo.testfire.net/sendFeedback
host: demo.testfire.net
accept-encoding: gzip, deflate
connection: keep-alive
user-agent: DAST-Security-Auditor/1.0 (+authorized-security-assessment)
accept: */*
cookie: JSESSIONID=4F0B4AB10DD4DD22B9B11DA8BDA795BC; AltoroAccounts=ODAwMDAyflNhdmluZ3N+LTguOTk5OTk3NDMyMDM3Nzc1RTI2fDgwMDAwM35DaGVja2luZ345LjAwMDAxNzc1MjQ1MTcwN0UyNnw0NTM5MDgyMDM5Mzk2Mjg4fkNyZWRpdCBDYXJkfi0xLjE4NDQ2NzQ0MDc4MDA1NjVFMjB8ODAwMDExfkNoZWNraW5nfjEuOTk5OTk5ODQ0ODJFMTF8ODAwMDEzfkNoZWNraW5nfjQwMC4wfDgwMDAxNH5TYXZpbmdzfi00NDc1LjB8ODAwMDE1fklSQX41MDAwLjB8ODAwMDE2flNhdmluZ3N+MC4wfDgwMDAxN35TYXZpbmdzfjAuMHw4MDAwMTh+U2F2aW5nc34wLjB8ODAwMDE5flNhdmluZ3N+MC4wfDgwMDAyMH5TYXZpbmdzfjEuMDY2MDIwNjk2Njk3NzQ1OEUyMXw4MDAwMjF+Q2hlY2tpbmd+MTcwLjB8
authorization: Basic anNtaXRoOmRlbW8xMjM0


```

#### HTTP Response Evidence
```http
HTTP/1.1 405 (3599.9ms)
server: Apache-Coyote/1.1
content-type: text/html;charset=utf-8
content-language: en
content-length: 1082
date: Fri, 09 Oct 2026 08:40:33 GMT
connection: close

<!doctype html><html lang="en"><head><title>HTTP Status 405 – Method Not Allowed</title><style type="text/css">H1 {font-family:Tahoma,Arial,sans-serif;color:white;background-color:#525D76;font-size:22px;} H2 {font-family:Tahoma,Arial,sans-serif;color:white;background-color:#525D76;font-size:16px;} H3 {font-family:Tahoma,Arial,sans-serif;color:white;background-color:#525D76;font-size:14px;} BODY {font-family:Tahoma,Arial,sans-serif;color:black;background-color:white;} B {font-family:Tahoma,Arial,
```

#### Remediation
> Configure the web server or reverse proxy to strip or suppress the Server header.

---

### 69. [HIGH] Server-Side Includes (SSI) Injection in Parameter 'cfile'

* **Detector Plugin:** `ssii`
* **Evidence Type:** `screenshot`
* **Affected URL:** `POST http://demo.testfire.net/sendFeedback` `[cfile]`

#### Description
Parameter 'cfile' is vulnerable to SSI Injection. The web server evaluated the injected SSI directive prior to serving the HTML response.

#### Technical Evidence
```text
HTTP Traffic Evidence:
Injected SSI Directive: <!--#echo var="DATE_LOCAL"-->
Evaluated Output: Matched token '202'
Technique: SSI Date directive
```

#### Visual Screenshot Evidence
![Screenshot Evidence](C:\Users\HP\OneDrive\Desktop\SCANNER\evidence\screenshots\ssii\term_016_ssii_cfile_91214c.png)
*File Path: `C:\Users\HP\OneDrive\Desktop\SCANNER\evidence\screenshots\ssii\term_016_ssii_cfile_91214c.png`*

#### HTTP Request Evidence
```http
POST http://demo.testfire.net/sendFeedback
host: demo.testfire.net
accept-encoding: gzip, deflate
connection: keep-alive
user-agent: DAST-Security-Auditor/1.0 (+authorized-security-assessment)
accept: */*
cookie: JSESSIONID=4F0B4AB10DD4DD22B9B11DA8BDA795BC; AltoroAccounts=ODAwMDAyflNhdmluZ3N+LTguOTk5OTk3NDMyMDM3Nzc1RTI2fDgwMDAwM35DaGVja2luZ345LjAwMDAxNzc1MjQ1MTcwN0UyNnw0NTM5MDgyMDM5Mzk2Mjg4fkNyZWRpdCBDYXJkfi0xLjE4NDQ2NzQ0MDc4MDA1NjVFMjB8ODAwMDExfkNoZWNraW5nfjEuOTk5OTk5ODQ0ODJFMTF8ODAwMDEzfkNoZWNraW5nfjQwMC4wfDgwMDAxNH5TYXZpbmdzfi00NDc1LjB8ODAwMDE1fklSQX41MDAwLjB8ODAwMDE2flNhdmluZ3N+MC4wfDgwMDAxN35TYXZpbmdzfjAuMHw4MDAwMTh+U2F2aW5nc34wLjB8ODAwMDE5flNhdmluZ3N+MC4wfDgwMDAyMH5TYXZpbmdzfjEuMDY2MDIwNjk2Njk3NzQ1OEUyMXw4MDAwMjF+Q2hlY2tpbmd+MTcwLjB8
content-length: 133
content-type: application/x-www-form-urlencoded
authorization: Basic anNtaXRoOmRlbW8xMjM0

{'cfile': '<!--#echo var="DATE_LOCAL"-->', 'name': '', 'email_addr': 'test', 'subject': 'test', 'comments': 'test', 'submit': ' Submit ', 'reset': ' Clear Form '}
```

#### HTTP Response Evidence
```http
HTTP/1.1 200 (289.2ms)
server: Apache-Coyote/1.1
content-type: text/html;charset=ISO-8859-1
content-length: 7045
date: Fri, 09 Oct 2026 08:40:46 GMT





 

    
    



 

<!-- BEGIN HEADER -->
<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">

<html xmlns="http://www.w3.org/1999/xhtml" xml:lang="en" >



<head>
	<title>Altoro Mutual</title>
  <meta http-equiv="Content-Type" content="text/html; charset=iso-8859-1" />
  <link href="/style.css" rel="stylesheet" type="text/css" />
</head>
<body style="margin-top:5px;">

<div id="header" style="margin-bottom:5px; width: 99%;
```

#### Remediation
> Disable Server-Side Includes (SSI) execution in the web server configuration or sanitize HTML comment syntax.

---

### 70. [HIGH] Stored Cross-Site Scripting (XSS) in Form Field 'name'

* **Detector Plugin:** `stored_xss`
* **Evidence Type:** `screenshot`
* **Affected URL:** `POST http://demo.testfire.net/sendFeedback` `[name]`

#### Description
Form field 'name' stores arbitrary HTML/JS markup and renders it unencoded.

#### Technical Evidence
```text
Stored XSS confirmed. Injected payload '<script>document.body.style.backgroundColor='red';document.body.insertAdjacentHTML('afterbegin','<h1>dastXSS</h1>')</script>' persisted in backend and rendered without encoding in subsequent page retrieval.
```

#### Visual Screenshot Evidence
![Screenshot Evidence](C:\Users\HP\OneDrive\Desktop\SCANNER\evidence\screenshots\stored_xss\step_017_stored_xss_name_evidence_c9ceae.png)
*File Path: `C:\Users\HP\OneDrive\Desktop\SCANNER\evidence\screenshots\stored_xss\step_017_stored_xss_name_evidence_c9ceae.png`*

#### Remediation
> Contextually encode all user-supplied output (HTML entity encoding) and sanitize storage inputs.

---

### 71. [HIGH] Reflected Cross-Site Scripting (XSS) in Form Field 'name'

* **Detector Plugin:** `xss`
* **Evidence Type:** `screenshot`
* **Affected URL:** `POST http://demo.testfire.net/sendFeedback` `[name]`

#### Description
Form field 'name' is vulnerable to reflected Cross-Site Scripting (XSS).

#### Technical Evidence
```text
Visual XSS confirmed. Injected payload '<script>document.body.style.backgroundColor='red';document.body.insertAdjacentHTML('afterbegin','<h1>dastXSS</h1>')</script>' executed in DOM with visual indicators.
```

#### Visual Screenshot Evidence
![Screenshot Evidence](C:\Users\HP\OneDrive\Desktop\SCANNER\evidence\screenshots\xss\step_018_xss_name_evidence_9a9c90.png)
*File Path: `C:\Users\HP\OneDrive\Desktop\SCANNER\evidence\screenshots\xss\step_018_xss_name_evidence_9a9c90.png`*

#### Remediation
> Contextually encode all user-supplied output (e.g. HTML entity encoding) and enforce a strict CSP.

---

### 72. [MEDIUM] Missing Clickjacking Defensive Framing Protections

* **Detector Plugin:** `clickjacking`
* **Evidence Type:** `http_traffic`
* **Affected URL:** `GET http://demo.testfire.net/feedback.jsp`

#### Description
The page lacks both the X-Frame-Options header and CSP frame-ancestors directive. An attacker can frame this target within a transparent <iframe> on a malicious domain to trick authenticated users into clicking sensitive UI buttons (Clickjacking).

#### Technical Evidence
```text
HTTP Response Header Evidence:
X-Frame-Options Header: Missing
CSP frame-ancestors Directive: Missing
```

#### HTTP Request Evidence
```http
GET http://demo.testfire.net/feedback.jsp
host: demo.testfire.net
accept-encoding: gzip, deflate
connection: keep-alive
user-agent: DAST-Security-Auditor/1.0 (+authorized-security-assessment)
accept: */*
cookie: JSESSIONID=4F0B4AB10DD4DD22B9B11DA8BDA795BC; AltoroAccounts=ODAwMDAyflNhdmluZ3N+LTguOTk5OTk3NDMyMDM3Nzc1RTI2fDgwMDAwM35DaGVja2luZ345LjAwMDAxNzc1MjQ1MTcwN0UyNnw0NTM5MDgyMDM5Mzk2Mjg4fkNyZWRpdCBDYXJkfi0xLjE4NDQ2NzQ0MDc4MDA1NjVFMjB8ODAwMDExfkNoZWNraW5nfjEuOTk5OTk5ODQ0ODJFMTF8ODAwMDEzfkNoZWNraW5nfjQwMC4wfDgwMDAxNH5TYXZpbmdzfi00NDc1LjB8ODAwMDE1fklSQX41MDAwLjB8ODAwMDE2flNhdmluZ3N+MC4wfDgwMDAxN35TYXZpbmdzfjAuMHw4MDAwMTh+U2F2aW5nc34wLjB8ODAwMDE5flNhdmluZ3N+MC4wfDgwMDAyMH5TYXZpbmdzfjEuMDY2MDIwNjk2Njk3NzQ1OEUyMXw4MDAwMjF+Q2hlY2tpbmd+MTcwLjB8
authorization: Basic anNtaXRoOmRlbW8xMjM0


```

#### HTTP Response Evidence
```http
HTTP/1.1 200 (397.7ms)
server: Apache-Coyote/1.1
content-type: text/html;charset=ISO-8859-1
transfer-encoding: chunked
date: Fri, 09 Oct 2026 08:41:02 GMT


    
 
    

 

<!-- BEGIN HEADER -->
<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">

<html xmlns="http://www.w3.org/1999/xhtml" xml:lang="en" >



<head>
	<title>Altoro Mutual</title>
  <meta http-equiv="Content-Type" content="text/html; charset=iso-8859-1" />
  <link href="/style.css" rel="stylesheet" type="text/css" />
</head>
<body style="margin-top:5px;">

<div id="header" style="margin-bottom:5px; width: 99%;">
  <
```

#### Remediation
> Set 'X-Frame-Options: SAMEORIGIN' or 'Content-Security-Policy: frame-ancestors 'self''.

---

### 73. [MEDIUM] Missing Anti-CSRF Token in State-Changing Form

* **Detector Plugin:** `csrf`
* **Evidence Type:** `screenshot`
* **Affected URL:** `POST http://demo.testfire.net/feedback.jsp`

#### Description
The form uses HTTP POST to perform sensitive state-changing operations without including a synchronized anti-CSRF token. If user sessions rely on ambient credentials (cookies), an external attacker can induce victim browsers to perform unauthorized actions.

#### Technical Evidence
```text
DOM Form Evidence:
Form Method: POST
Form Action: sendFeedback
Input Fields: cfile, name, email_addr, subject, comments, submit, reset
Form HTML Snippet:
<form action="sendFeedback" method="post" name="cmt">
<!--- Dave- Hard code this into the final script - Possible security problem.
		  Re-generated every Tuesday and old files are saved to .bak format at L:\backup\website\oldfiles    --->
<input name="cfile" type="hidden" value="comments.txt"/>
<table border="0">
<tr>
<td align="right">To:</td>
<t...
Observed: No hidden anti-CSRF token input field detected inside form.
```

#### Visual Screenshot Evidence
![Screenshot Evidence](C:\Users\HP\OneDrive\Desktop\SCANNER\evidence\screenshots\csrf\step_019_csrf_form_evidence_9f45ed.png)
*File Path: `C:\Users\HP\OneDrive\Desktop\SCANNER\evidence\screenshots\csrf\step_019_csrf_form_evidence_9f45ed.png`*

#### HTTP Request Evidence
```http
GET http://demo.testfire.net/feedback.jsp
host: demo.testfire.net
accept-encoding: gzip, deflate
connection: keep-alive
user-agent: DAST-Security-Auditor/1.0 (+authorized-security-assessment)
accept: */*
cookie: JSESSIONID=4F0B4AB10DD4DD22B9B11DA8BDA795BC; AltoroAccounts=ODAwMDAyflNhdmluZ3N+LTguOTk5OTk3NDMyMDM3Nzc1RTI2fDgwMDAwM35DaGVja2luZ345LjAwMDAxNzc1MjQ1MTcwN0UyNnw0NTM5MDgyMDM5Mzk2Mjg4fkNyZWRpdCBDYXJkfi0xLjE4NDQ2NzQ0MDc4MDA1NjVFMjB8ODAwMDExfkNoZWNraW5nfjEuOTk5OTk5ODQ0ODJFMTF8ODAwMDEzfkNoZWNraW5nfjQwMC4wfDgwMDAxNH5TYXZpbmdzfi00NDc1LjB8ODAwMDE1fklSQX41MDAwLjB8ODAwMDE2flNhdmluZ3N+MC4wfDgwMDAxN35TYXZpbmdzfjAuMHw4MDAwMTh+U2F2aW5nc34wLjB8ODAwMDE5flNhdmluZ3N+MC4wfDgwMDAyMH5TYXZpbmdzfjEuMDY2MDIwNjk2Njk3NzQ1OEUyMXw4MDAwMjF+Q2hlY2tpbmd+MTcwLjB8
authorization: Basic anNtaXRoOmRlbW8xMjM0


```

#### HTTP Response Evidence
```http
HTTP/1.1 200 (287.6ms)
server: Apache-Coyote/1.1
content-type: text/html;charset=ISO-8859-1
transfer-encoding: chunked
date: Fri, 09 Oct 2026 08:41:13 GMT


    
 
    

 

<!-- BEGIN HEADER -->
<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">

<html xmlns="http://www.w3.org/1999/xhtml" xml:lang="en" >



<head>
	<title>Altoro Mutual</title>
  <meta http-equiv="Content-Type" content="text/html; charset=iso-8859-1" />
  <link href="/style.css" rel="stylesheet" type="text/css" />
</head>
<body style="margin-top:5px;">

<div id="header" style="margin-bottom:5px; width: 99%;">
  <
```

#### Remediation
> 1. Convert sensitive state-changing actions from HTTP GET to HTTP POST.
2. Include cryptographically random, unpredictable anti-CSRF tokens in all state-changing HTML forms.
3. Enforce 'SameSite=Lax' or 'SameSite=Strict' on session cookies.
4. Require re-authentication (current password) for critical account actions (e.g., password change, email change).

---

### 74. [MEDIUM] Missing Security Header: Content-Security-Policy

* **Detector Plugin:** `security_headers`
* **Evidence Type:** `http_traffic`
* **Affected URL:** `GET http://demo.testfire.net/feedback.jsp`

#### Description
Protects against Cross-Site Scripting (XSS), data injection, and clickjacking attacks.

#### Technical Evidence
```text
HTTP Traffic Evidence:
Missing Recommended Security Header: Content-Security-Policy
Status Code: 200
Observed Headers: content-type, date, server, transfer-encoding
```

#### HTTP Request Evidence
```http
GET http://demo.testfire.net/feedback.jsp
host: demo.testfire.net
accept-encoding: gzip, deflate
connection: keep-alive
user-agent: DAST-Security-Auditor/1.0 (+authorized-security-assessment)
accept: */*
cookie: JSESSIONID=4F0B4AB10DD4DD22B9B11DA8BDA795BC; AltoroAccounts=ODAwMDAyflNhdmluZ3N+LTguOTk5OTk3NDMyMDM3Nzc1RTI2fDgwMDAwM35DaGVja2luZ345LjAwMDAxNzc1MjQ1MTcwN0UyNnw0NTM5MDgyMDM5Mzk2Mjg4fkNyZWRpdCBDYXJkfi0xLjE4NDQ2NzQ0MDc4MDA1NjVFMjB8ODAwMDExfkNoZWNraW5nfjEuOTk5OTk5ODQ0ODJFMTF8ODAwMDEzfkNoZWNraW5nfjQwMC4wfDgwMDAxNH5TYXZpbmdzfi00NDc1LjB8ODAwMDE1fklSQX41MDAwLjB8ODAwMDE2flNhdmluZ3N+MC4wfDgwMDAxN35TYXZpbmdzfjAuMHw4MDAwMTh+U2F2aW5nc34wLjB8ODAwMDE5flNhdmluZ3N+MC4wfDgwMDAyMH5TYXZpbmdzfjEuMDY2MDIwNjk2Njk3NzQ1OEUyMXw4MDAwMjF+Q2hlY2tpbmd+MTcwLjB8
authorization: Basic anNtaXRoOmRlbW8xMjM0


```

#### HTTP Response Evidence
```http
HTTP/1.1 200 (437.6ms)
server: Apache-Coyote/1.1
content-type: text/html;charset=ISO-8859-1
transfer-encoding: chunked
date: Fri, 09 Oct 2026 08:41:24 GMT


    
 
    

 

<!-- BEGIN HEADER -->
<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">

<html xmlns="http://www.w3.org/1999/xhtml" xml:lang="en" >



<head>
	<title>Altoro Mutual</title>
  <meta http-equiv="Content-Type" content="text/html; charset=iso-8859-1" />
  <link href="/style.css" rel="stylesheet" type="text/css" />
</head>
<body style="margin-top:5px;">

<div id="header" style="margin-bottom:5px; width: 99%;">
  <
```

#### Remediation
> Define and enforce a strict Content-Security-Policy (CSP) restricting trusted sources.

---

### 75. [MEDIUM] Missing Security Header: X-Frame-Options

* **Detector Plugin:** `security_headers`
* **Evidence Type:** `http_traffic`
* **Affected URL:** `GET http://demo.testfire.net/feedback.jsp`

#### Description
Defends against UI redress attacks (Clickjacking) by disallowing framing.

#### Technical Evidence
```text
HTTP Traffic Evidence:
Missing Recommended Security Header: X-Frame-Options
Status Code: 200
Observed Headers: content-type, date, server, transfer-encoding
```

#### HTTP Request Evidence
```http
GET http://demo.testfire.net/feedback.jsp
host: demo.testfire.net
accept-encoding: gzip, deflate
connection: keep-alive
user-agent: DAST-Security-Auditor/1.0 (+authorized-security-assessment)
accept: */*
cookie: JSESSIONID=4F0B4AB10DD4DD22B9B11DA8BDA795BC; AltoroAccounts=ODAwMDAyflNhdmluZ3N+LTguOTk5OTk3NDMyMDM3Nzc1RTI2fDgwMDAwM35DaGVja2luZ345LjAwMDAxNzc1MjQ1MTcwN0UyNnw0NTM5MDgyMDM5Mzk2Mjg4fkNyZWRpdCBDYXJkfi0xLjE4NDQ2NzQ0MDc4MDA1NjVFMjB8ODAwMDExfkNoZWNraW5nfjEuOTk5OTk5ODQ0ODJFMTF8ODAwMDEzfkNoZWNraW5nfjQwMC4wfDgwMDAxNH5TYXZpbmdzfi00NDc1LjB8ODAwMDE1fklSQX41MDAwLjB8ODAwMDE2flNhdmluZ3N+MC4wfDgwMDAxN35TYXZpbmdzfjAuMHw4MDAwMTh+U2F2aW5nc34wLjB8ODAwMDE5flNhdmluZ3N+MC4wfDgwMDAyMH5TYXZpbmdzfjEuMDY2MDIwNjk2Njk3NzQ1OEUyMXw4MDAwMjF+Q2hlY2tpbmd+MTcwLjB8
authorization: Basic anNtaXRoOmRlbW8xMjM0


```

#### HTTP Response Evidence
```http
HTTP/1.1 200 (437.6ms)
server: Apache-Coyote/1.1
content-type: text/html;charset=ISO-8859-1
transfer-encoding: chunked
date: Fri, 09 Oct 2026 08:41:24 GMT


    
 
    

 

<!-- BEGIN HEADER -->
<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">

<html xmlns="http://www.w3.org/1999/xhtml" xml:lang="en" >



<head>
	<title>Altoro Mutual</title>
  <meta http-equiv="Content-Type" content="text/html; charset=iso-8859-1" />
  <link href="/style.css" rel="stylesheet" type="text/css" />
</head>
<body style="margin-top:5px;">

<div id="header" style="margin-bottom:5px; width: 99%;">
  <
```

#### Remediation
> Set X-Frame-Options to DENY or SAMEORIGIN.

---

### 76. [LOW] Missing Security Header: X-Content-Type-Options

* **Detector Plugin:** `security_headers`
* **Evidence Type:** `http_traffic`
* **Affected URL:** `GET http://demo.testfire.net/feedback.jsp`

#### Description
Prevents MIME-type sniffing which can lead to script execution via non-executable files.

#### Technical Evidence
```text
HTTP Traffic Evidence:
Missing Recommended Security Header: X-Content-Type-Options
Status Code: 200
Observed Headers: content-type, date, server, transfer-encoding
```

#### HTTP Request Evidence
```http
GET http://demo.testfire.net/feedback.jsp
host: demo.testfire.net
accept-encoding: gzip, deflate
connection: keep-alive
user-agent: DAST-Security-Auditor/1.0 (+authorized-security-assessment)
accept: */*
cookie: JSESSIONID=4F0B4AB10DD4DD22B9B11DA8BDA795BC; AltoroAccounts=ODAwMDAyflNhdmluZ3N+LTguOTk5OTk3NDMyMDM3Nzc1RTI2fDgwMDAwM35DaGVja2luZ345LjAwMDAxNzc1MjQ1MTcwN0UyNnw0NTM5MDgyMDM5Mzk2Mjg4fkNyZWRpdCBDYXJkfi0xLjE4NDQ2NzQ0MDc4MDA1NjVFMjB8ODAwMDExfkNoZWNraW5nfjEuOTk5OTk5ODQ0ODJFMTF8ODAwMDEzfkNoZWNraW5nfjQwMC4wfDgwMDAxNH5TYXZpbmdzfi00NDc1LjB8ODAwMDE1fklSQX41MDAwLjB8ODAwMDE2flNhdmluZ3N+MC4wfDgwMDAxN35TYXZpbmdzfjAuMHw4MDAwMTh+U2F2aW5nc34wLjB8ODAwMDE5flNhdmluZ3N+MC4wfDgwMDAyMH5TYXZpbmdzfjEuMDY2MDIwNjk2Njk3NzQ1OEUyMXw4MDAwMjF+Q2hlY2tpbmd+MTcwLjB8
authorization: Basic anNtaXRoOmRlbW8xMjM0


```

#### HTTP Response Evidence
```http
HTTP/1.1 200 (437.6ms)
server: Apache-Coyote/1.1
content-type: text/html;charset=ISO-8859-1
transfer-encoding: chunked
date: Fri, 09 Oct 2026 08:41:24 GMT


    
 
    

 

<!-- BEGIN HEADER -->
<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">

<html xmlns="http://www.w3.org/1999/xhtml" xml:lang="en" >



<head>
	<title>Altoro Mutual</title>
  <meta http-equiv="Content-Type" content="text/html; charset=iso-8859-1" />
  <link href="/style.css" rel="stylesheet" type="text/css" />
</head>
<body style="margin-top:5px;">

<div id="header" style="margin-bottom:5px; width: 99%;">
  <
```

#### Remediation
> Set X-Content-Type-Options to 'nosniff'.

---

### 77. [LOW] Missing Security Header: Referrer-Policy

* **Detector Plugin:** `security_headers`
* **Evidence Type:** `http_traffic`
* **Affected URL:** `GET http://demo.testfire.net/feedback.jsp`

#### Description
Protects sensitive URLs and query parameters from leaking via the HTTP Referer header.

#### Technical Evidence
```text
HTTP Traffic Evidence:
Missing Recommended Security Header: Referrer-Policy
Status Code: 200
Observed Headers: content-type, date, server, transfer-encoding
```

#### HTTP Request Evidence
```http
GET http://demo.testfire.net/feedback.jsp
host: demo.testfire.net
accept-encoding: gzip, deflate
connection: keep-alive
user-agent: DAST-Security-Auditor/1.0 (+authorized-security-assessment)
accept: */*
cookie: JSESSIONID=4F0B4AB10DD4DD22B9B11DA8BDA795BC; AltoroAccounts=ODAwMDAyflNhdmluZ3N+LTguOTk5OTk3NDMyMDM3Nzc1RTI2fDgwMDAwM35DaGVja2luZ345LjAwMDAxNzc1MjQ1MTcwN0UyNnw0NTM5MDgyMDM5Mzk2Mjg4fkNyZWRpdCBDYXJkfi0xLjE4NDQ2NzQ0MDc4MDA1NjVFMjB8ODAwMDExfkNoZWNraW5nfjEuOTk5OTk5ODQ0ODJFMTF8ODAwMDEzfkNoZWNraW5nfjQwMC4wfDgwMDAxNH5TYXZpbmdzfi00NDc1LjB8ODAwMDE1fklSQX41MDAwLjB8ODAwMDE2flNhdmluZ3N+MC4wfDgwMDAxN35TYXZpbmdzfjAuMHw4MDAwMTh+U2F2aW5nc34wLjB8ODAwMDE5flNhdmluZ3N+MC4wfDgwMDAyMH5TYXZpbmdzfjEuMDY2MDIwNjk2Njk3NzQ1OEUyMXw4MDAwMjF+Q2hlY2tpbmd+MTcwLjB8
authorization: Basic anNtaXRoOmRlbW8xMjM0


```

#### HTTP Response Evidence
```http
HTTP/1.1 200 (437.6ms)
server: Apache-Coyote/1.1
content-type: text/html;charset=ISO-8859-1
transfer-encoding: chunked
date: Fri, 09 Oct 2026 08:41:24 GMT


    
 
    

 

<!-- BEGIN HEADER -->
<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">

<html xmlns="http://www.w3.org/1999/xhtml" xml:lang="en" >



<head>
	<title>Altoro Mutual</title>
  <meta http-equiv="Content-Type" content="text/html; charset=iso-8859-1" />
  <link href="/style.css" rel="stylesheet" type="text/css" />
</head>
<body style="margin-top:5px;">

<div id="header" style="margin-bottom:5px; width: 99%;">
  <
```

#### Remediation
> Configure Referrer-Policy to 'strict-origin-when-cross-origin' or 'no-referrer'.

---

### 78. [LOW] Information Disclosure: Server Header

* **Detector Plugin:** `security_headers`
* **Evidence Type:** `http_traffic`
* **Affected URL:** `GET http://demo.testfire.net/feedback.jsp`

#### Description
Web server vendor and version banner disclosure: 'Apache-Coyote/1.1' was returned in the server response.

#### Technical Evidence
```text
HTTP Traffic Evidence:
Disclosed Header: Server: Apache-Coyote/1.1
Status Code: 200
```

#### HTTP Request Evidence
```http
GET http://demo.testfire.net/feedback.jsp
host: demo.testfire.net
accept-encoding: gzip, deflate
connection: keep-alive
user-agent: DAST-Security-Auditor/1.0 (+authorized-security-assessment)
accept: */*
cookie: JSESSIONID=4F0B4AB10DD4DD22B9B11DA8BDA795BC; AltoroAccounts=ODAwMDAyflNhdmluZ3N+LTguOTk5OTk3NDMyMDM3Nzc1RTI2fDgwMDAwM35DaGVja2luZ345LjAwMDAxNzc1MjQ1MTcwN0UyNnw0NTM5MDgyMDM5Mzk2Mjg4fkNyZWRpdCBDYXJkfi0xLjE4NDQ2NzQ0MDc4MDA1NjVFMjB8ODAwMDExfkNoZWNraW5nfjEuOTk5OTk5ODQ0ODJFMTF8ODAwMDEzfkNoZWNraW5nfjQwMC4wfDgwMDAxNH5TYXZpbmdzfi00NDc1LjB8ODAwMDE1fklSQX41MDAwLjB8ODAwMDE2flNhdmluZ3N+MC4wfDgwMDAxN35TYXZpbmdzfjAuMHw4MDAwMTh+U2F2aW5nc34wLjB8ODAwMDE5flNhdmluZ3N+MC4wfDgwMDAyMH5TYXZpbmdzfjEuMDY2MDIwNjk2Njk3NzQ1OEUyMXw4MDAwMjF+Q2hlY2tpbmd+MTcwLjB8
authorization: Basic anNtaXRoOmRlbW8xMjM0


```

#### HTTP Response Evidence
```http
HTTP/1.1 200 (437.6ms)
server: Apache-Coyote/1.1
content-type: text/html;charset=ISO-8859-1
transfer-encoding: chunked
date: Fri, 09 Oct 2026 08:41:24 GMT


    
 
    

 

<!-- BEGIN HEADER -->
<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">

<html xmlns="http://www.w3.org/1999/xhtml" xml:lang="en" >



<head>
	<title>Altoro Mutual</title>
  <meta http-equiv="Content-Type" content="text/html; charset=iso-8859-1" />
  <link href="/style.css" rel="stylesheet" type="text/css" />
</head>
<body style="margin-top:5px;">

<div id="header" style="margin-bottom:5px; width: 99%;">
  <
```

#### Remediation
> Configure the web server or reverse proxy to strip or suppress the Server header.

---

### 79. [HIGH] Stored Cross-Site Scripting (XSS) in Form Field 'query'

* **Detector Plugin:** `stored_xss`
* **Evidence Type:** `screenshot`
* **Affected URL:** `GET http://demo.testfire.net/search.jsp` `[query]`

#### Description
Form field 'query' stores arbitrary HTML/JS markup and renders it unencoded.

#### Technical Evidence
```text
Stored XSS confirmed. Injected payload '<script>document.body.style.backgroundColor='red';document.body.insertAdjacentHTML('afterbegin','<h1>dastXSS</h1>')</script>' persisted in backend and rendered without encoding in subsequent page retrieval.
```

#### Visual Screenshot Evidence
![Screenshot Evidence](C:\Users\HP\OneDrive\Desktop\SCANNER\evidence\screenshots\stored_xss\step_020_stored_xss_query_evidence_4f8267.png)
*File Path: `C:\Users\HP\OneDrive\Desktop\SCANNER\evidence\screenshots\stored_xss\step_020_stored_xss_query_evidence_4f8267.png`*

#### Remediation
> Contextually encode all user-supplied output (HTML entity encoding) and sanitize storage inputs.

---

### 80. [HIGH] Reflected Cross-Site Scripting (XSS) in Form Field 'query'

* **Detector Plugin:** `xss`
* **Evidence Type:** `screenshot`
* **Affected URL:** `GET http://demo.testfire.net/search.jsp` `[query]`

#### Description
Form field 'query' is vulnerable to reflected Cross-Site Scripting (XSS).

#### Technical Evidence
```text
Visual XSS confirmed. Injected payload '<script>document.body.style.backgroundColor='red';document.body.insertAdjacentHTML('afterbegin','<h1>dastXSS</h1>')</script>' executed in DOM with visual indicators.
```

#### Visual Screenshot Evidence
![Screenshot Evidence](C:\Users\HP\OneDrive\Desktop\SCANNER\evidence\screenshots\xss\step_021_xss_query_evidence_5c25d5.png)
*File Path: `C:\Users\HP\OneDrive\Desktop\SCANNER\evidence\screenshots\xss\step_021_xss_query_evidence_5c25d5.png`*

#### Remediation
> Contextually encode all user-supplied output (e.g. HTML entity encoding) and enforce a strict CSP.

---

### 81. [HIGH] Reflected Cross-Site Scripting (XSS) in Form Field 'name'

* **Detector Plugin:** `xss`
* **Evidence Type:** `screenshot`
* **Affected URL:** `POST http://demo.testfire.net/sendFeedback` `[name]`

#### Description
Form field 'name' is vulnerable to reflected Cross-Site Scripting (XSS).

#### Technical Evidence
```text
Visual XSS confirmed. Injected payload '<script>document.body.style.backgroundColor='red';document.body.insertAdjacentHTML('afterbegin','<h1>dastXSS</h1>')</script>' executed in DOM with visual indicators.
```

#### Visual Screenshot Evidence
![Screenshot Evidence](C:\Users\HP\OneDrive\Desktop\SCANNER\evidence\screenshots\xss\step_022_xss_name_evidence_1b8f71.png)
*File Path: `C:\Users\HP\OneDrive\Desktop\SCANNER\evidence\screenshots\xss\step_022_xss_name_evidence_1b8f71.png`*

#### Remediation
> Contextually encode all user-supplied output (e.g. HTML entity encoding) and enforce a strict CSP.

---

## Scanned Endpoints (10)

| Method | URL Path | Parameters |
| :---: | :--- | :--- |
| `GET` | `http://demo.testfire.net/search.jsp` | `query` |
| `GET` | `http://demo.testfire.net/` | *None* |
| `GET` | `http://demo.testfire.net/bank/showAccount` | `listAccounts` |
| `GET` | `http://demo.testfire.net/bank/main.jsp` | *None* |
| `GET` | `http://demo.testfire.net/style.css` | *None* |
| `GET` | `http://demo.testfire.net/index.jsp` | *None* |
| `GET` | `http://demo.testfire.net/logout.jsp` | *None* |
| `GET` | `http://demo.testfire.net/index.jsp` | `content` |
| `POST` | `http://demo.testfire.net/sendFeedback` | `cfile`, `comments`, `email_addr`, `name`, `reset`, `subject`, `submit` |
| `GET` | `http://demo.testfire.net/feedback.jsp` | *None* |

## Detector Execution Times

| Detector | Execution Time |
| :--- | :---: |
| `dom_xss` | 2420.95s |
| `command_injection` | 323.75s |
| `sqli` | 275.77s |
| `stored_xss` | 151.13s |
| `file_inclusion` | 83.88s |
| `php_code_injection` | 29.59s |
| `xpath_injection` | 24.66s |
| `xss` | 24.39s |
| `cookies` | 23.64s |
| `weak_session_ids` | 18.32s |
| `ssti` | 17.82s |
| `clickjacking` | 14.98s |
| `csrf` | 10.16s |
| `security_headers` | 7.23s |
| `ssii` | 6.50s |
| `html_injection` | 5.38s |
| `crlf` | 4.86s |
| `insecure_captcha` | 4.62s |
| `file_upload` | 4.27s |
| `javascript` | 4.18s |
| `csp_bypass` | 3.75s |
| `cors` | 3.62s |
| `hpp` | 3.10s |
| `xxe` | 1.54s |
| `ssrf` | 0.00s |
| `open_redirect` | 0.00s |
| `brute_force` | 0.00s |
