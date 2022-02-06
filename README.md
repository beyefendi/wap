# Web application	penetration test - LABware

## A) Server-side Attacks

### 0x01 - Information disclosure

- Error messages
- Debug page
- Source code disclosure via backup files
- Authentication bypass via information disclosure
- Information disclosure in version control history

### 0x02 - Directory traversal

- Reading arbitrary files via file path traversal
- Bypassing preventions
  - Traversal sequences blocked with absolute path bypass
  - Traversal sequences stripped non-recursively
  - Traversal sequences stripped with superfluous URL-decode
  - Validation of start of the path
  - Validation of file extension with null byte bypass

### 0x03 - Authentication vulnerabilities

- Password-based login
  - Username enumeration via different responses
  - Username enumeration via subtly different responses
  - Username enumeration via response timing
  - Broken brute-force protection, IP block
  - Username enumeration via account lock
  - Broken brute-force protection, multiple credentials per request
- Multi-factor authentication
  - 2FA simple bypass
  - 2FA broken logic
  - 2FA bypass using a brute-force attack
- Other authentication mechanisms
  - Brute-forcing a stay-logged-in cookie
- Offline password cracking
- Password reset broken logic
- Password reset poisoning via middleware
- Password brute-force via password change

### 0x04 - Access control vulnerabilities (Privilege esacalation)

- Unprotected admin functionality
- Unprotected admin functionality with unpredictable URL
- User role controlled by request parameter
- User role can be modified in the user profile
- URL-based access control can be circumvented
- Method-based access control can be circumvented
- User ID controlled by request parameter 
- User ID controlled by request parameter, with unpredictable user IDs 
- User ID controlled by request parameter with data leakage in redirect 
- User ID controlled by request parameter with password disclosure
- Insecure direct object references (IDOR)
- Multi-step process with no access control on one step 
- Referer-based access control 

### 0x05 - SQL injection

- SQL injection UNION attacks
  - determining the number of columns returned by the query
  - finding a column containing text
  - retrieving data from other tables
  - retrieving multiple values in a single column
- Examining the database in SQL injection attacks
  - querying the database type and version on Oracle
  - querying the database type and version on MySQL and Microsoft
  - listing the database contents on non-Oracle databases
  - listing the database contents on Oracle
- Blind SQL injection
  - with conditional responses
  - with conditional errors
  - with time delays
  - with time delays and information retrieval
  - with out-of-band interaction
  - with out-of-band data exfiltration
- SQL injection vulnerability in WHERE clause allowing retrieval of hidden data
- SQL injection vulnerability allowing login bypass

### 0x06 - OS command injection

- Simple case
- Blind OS command injection 
  - with time delays
  - with output redirection
  - with out-of-band interaction
  - with out-of-band data exfiltration

### 0x07 - File upload vulnerabilities

- Remote code execution via web shell upload
- Web shell upload via Content-Type restriction bypass
- Web shell upload via path traversal
- Web shell upload via extension blacklist bypass
- Web shell upload via obfuscated file extension
- Remote code execution via polyglot web shell upload
- Web shell upload via race condition

### 0x08 - Server-side request forgery (SSRF)

- Basic SSRF against the local server
- Basic SSRF against another back-end system
- SSRF with blacklist-based input filter
- SSRF with whitelist-based input filter
- SSRF with filter bypass via open redirection vulnerability
- Blind SSRF vulnerabilities
  - Blind SSRF with out-of-band detection
  - Blind SSRF with Shellshock exploitation

### 0x09 - XXE (XML external entity) injection

- Exploiting XXE using external entities to retrieve files
- Exploiting XXE to perform SSRF attacks
- Blind XXE vulnerabilities
  - Blind XXE with out-of-band interaction
  - Blind XXE with out-of-band interaction via XML parameter entities
  - Exploiting blind XXE to exfiltrate data using a malicious external DTD
  - Exploiting blind XXE to retrieve data via error messages
- Exploiting XXE to retrieve data by repurposing a local DTD
- Exploiting XInclude to retrieve files
- Exploiting XXE via image file upload

### 0x0A - Business logic vulnerabilities

- Excessive trust in client-side controls
- High-level logic vulnerability
- Low-level logic flaw
- Inconsistent handling of exceptional input
- Inconsistent security controls
- Weak isolation on dual-use endpoint
- Insufficient workflow validation
- Authentication bypass via flawed state machine
- Flawed enforcement of business rules
- Infinite money logic flaw
- Authentication bypass via encryption oracle

## B) Client-side Attacks

### 0x0B - Cross-site scripting (XSS)

- Reflected XSS
  - Reflected XSS into HTML context with nothing encoded
- Stored XSS
  - Stored XSS into HTML context with nothing encoded
- DOM-based XSS
  - DOM XSS in document.write sink using source location.search
  - DOM XSS in document.write sink using source location.search inside a select element
  - DOM XSS in innerHTML sink using source location.search
  - DOM XSS in jQuery anchor href attribute sink using location.search source
  - DOM XSS in jQuery selector sink using a hashchange event
  - DOM XSS in AngularJS expression with angle brackets and double quotes HTML-encoded
  - Reflected DOM XSS
  - Stored DOM XSS
- Exploiting cross-site scripting vulnerabilities
  - Exploiting cross-site scripting to steal cookies
  - Exploiting cross-site scripting to capture passwords
  - Exploiting XSS to perform CSRF
- Reflected XSS into HTML context with most tags and attributes blocked
- Reflected XSS into HTML context with all tags blocked except custom ones
- Reflected XSS with event handlers and href attributes blocked
- Reflected XSS with some SVG markup allowed
- Reflected XSS into attribute with angle brackets HTML-encoded
- Stored XSS into anchor href attribute with double quotes HTML-encoded
- Reflected XSS in a canonical link tag
- Reflected XSS into a JavaScript string with single quote and backslash escaped
- Reflected XSS into a JavaScript string with angle brackets HTML encoded
- Reflected XSS into a JavaScript string with angle brackets and double quotes HTML-encoded and single quotes escaped
- Reflected XSS in a JavaScript URL with some characters blocked
- Stored XSS into onclick event with angle brackets and double quotes HTML-encoded and single quotes and backslash escaped
- Reflected XSS into a template literal with angle brackets, single, double quotes, backslash and backticks Unicode-escaped
- Cross-site scripting contexts
  - Reflected XSS with AngularJS sandbox escape without strings
  - Reflected XSS with AngularJS sandbox escape and CSP
- Content security policy (CSP)
  - Reflected XSS protected by CSP, with dangling markup attack
- Dangling markup injection
  - Reflected XSS protected by very strict CSP, with dangling markup attack
  - Reflected XSS protected by CSP, with CSP bypass

### 0x0C - Cross-site request forgery (CSRF)

- CSRF vulnerability with no defenses
- CSRF where token validation depends on the request method
- CSRF where token validation depends on token being present
- CSRF where the token is not tied to user session
- CSRF where token is tied to non-session cookie
- CSRF where token is duplicated in cookie
- CSRF where Referer validation depends on header being present
- CSRF with broken Referer validation

### 0x0D - Cross-origin resource sharing (CORS)

- CORS vulnerability with basic origin reflection
- CORS vulnerability with the trusted null origin
- CORS vulnerability with trusted insecure protocols
- CORS vulnerability with internal network pivot attack

### 0x0E - Clickjacking (UI redressing)

- Basic clickjacking with CSRF token protection
- Clickjacking with form input data prefilled from a URL parameter
- Clickjacking with a frame buster script
- Exploiting clickjacking vulnerability to trigger DOM-based XSS
- Multistep clickjacking

### 0x0F - DOM-based vulnerabilities

- DOM XSS using web messages
- DOM XSS using web messages and a JavaScript URL
- DOM XSS using web messages and JSON.parse
- DOM-based open redirection
- DOM-based cookie manipulation
- Exploiting DOM clobbering to enable XSS
- Clobbering DOM attributes to bypass HTML filters

### 0x10 - WebSockets vulnerabilities

- Manipulating WebSocket messages to exploit vulnerabilities
- Manipulating the WebSocket handshake to exploit vulnerabilities
- Cross-site WebSocket hijacking

## C) Advanced Attacks

### 0x11 - Insecure deserialization

- Modifying serialized objects
- Modifying serialized data types
- Using application functionality to exploit insecure deserialization
- Arbitrary object injection in PHP
- Exploiting Java deserialization with Apache Commons
- Exploiting PHP deserialization with a pre-built gadget chain
- Exploiting Ruby deserialization using a documented gadget chain
- Developing a custom gadget chain for Java deserialization
- Developing a custom gadget chain for PHP deserialization
- Using PHAR deserialization to deploy a custom gadget ch

### 0x12 - Server-side template injection

- Basic server-side template injection
- Basic server-side template injection (code context)
- Server-side template injection using documentation
- Server-side template injection in an unknown language with a documented exploit
- Server-side template injection with information disclosure via user-supplied objects
- Server-side template injection in a sandboxed environment
- Server-side template injection with a custom exploit

### 0x13 - Web cache poisoning

-  Web cache poisoning with an unkeyed header
-  Web cache poisoning with an unkeyed cookie
-  Web cache poisoning with multiple headers
-  Targeted web cache poisoning using an unknown header
-  Web cache poisoning to exploit a DOM vulnerability via a cache with strict cache-ability criteria
-  Combining web cache poisoning vulnerabilities
-  Web cache poisoning via an unkeyed query string
-  Web cache poisoning via an unkeyed query parameter
-  Parameter cloaking
-  Web cache poisoning via a fat GET request
-  URL normalization
-  Cache key injection
-  Internal cache poisoning
 
### 0x14 - HTTP Host header attacks

- Basic password reset poisoning
- Password reset poisoning via dangling markup
- Web cache poisoning via ambiguous requests
- Host header authentication bypass
- Routing-based SSRF
- SSRF via flawed request parsing

### 0x15 - HTTP request smuggling

- HTTP request smuggling, basic CL.TE vulnerability
- HTTP request smuggling, basic TE.CL vulnerability
- HTTP request smuggling, obfuscating the TE header
- HTTP request smuggling, confirming a CL.TE vulnerability via differential responses
- HTTP request smuggling, confirming a TE.CL vulnerability via differential responses
- Exploiting HTTP request smuggling to bypass front-end security controls, CL.TE vulnerability
- Exploiting HTTP request smuggling to bypass front-end security controls, TE.CL vulnerability
- Exploiting HTTP request smuggling to reveal front-end request rewriting
- Exploiting HTTP request smuggling to capture other users' requests
- Exploiting HTTP request smuggling to deliver reflected XSS
- Exploiting HTTP request smuggling to perform web cache poisoning
- Exploiting HTTP request smuggling to perform web cache deception
- Response queue poisoning via H2.TE request smuggling
- Bypassing access controls via HTTP/2 request tunneling
- Web cache poisoning via HTTP/2 request tunneling
- H2.CL request smuggling
- HTTP/2 request smuggling via CRLF injection
- HTTP/2 request splitting via CRLF injection

### 0x16 - OAuth 2.0 authentication vulnerabilities

- Authentication bypass via OAuth implicit flow
- Forced OAuth profile linking
- OAuth account hijacking via redirect_uri
- Stealing OAuth access tokens via an open redirect
- Stealing OAuth access tokens via a proxy page
- SSRF via OpenID dynamic client registration

## Reference

- Augmenting your manual testing with Burp Scanner
- Obfuscating attacks using encodings
