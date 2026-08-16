Static-Shield / htaccess-ip-guard (IPSentinel)
A lightweight, zero-database Website Firewall and IP restriction framework designed specifically for static HTML5 websites running on Apache servers.

Overview
htaccess-ip-guard (also known as IPSentinel or Static-Shield) acts as an edge gate deploy solution for legacy or static infrastructure. It intercepts incoming HTTP traffic, evaluates visitor IP addresses against a plain-text configuration file (restricted_ips.txt), and prompts restricted networks with an HTML5 static gatekeeper verification form. Once authenticated, visitors are issued a secure 30-day session cookie for seamless browsing.

Key Features
Zero-Database Requirement: Uses flat files (restricted_ips.txt) for lightning-fast lookups without MySQL or SQLite overhead.

Flexible IP Matching: Supports exact IPs, CIDR blocks (e.g., 10.0.0.0/22), wildcards (e.g., 172.16.*.*), and partial subnet blocks.

Smart Session Caching: Once verified via passcode, clients receive a secure, HttpOnly, SameSite-Lax cookie valid for 30 days.

Automatic .htaccess Injection: Safely prepends security routing rules without overwriting your existing server configurations.

Audit Logging: Logs all restricted access attempts and successful authentications to ip_auth_attempts.log.

File Structure & Alternative Names
Depending on how you wish to integrate or package this utility, the deployment script can be named:

setup-ip-restriction.php

install-ip-gate.php

edge-gate-deploy.php

Generated production files:

.htaccess — Rewrites and secures public asset downloads.

gate.php — Evaluates incoming IPs and renders the verification prompt.

verify.php — Validates passcodes and sets the secure bypass cookie.

restricted_ips.txt — Whitelist/blacklist control file for IP rules.

Quick Start & Installation
Upload: Upload your deployment script (e.g., deploy.php or install-ip-gate.php) to your website's public root directory (e.g., public_html/ or www/).

Execute: Run the installer via your browser:

Plaintext
https://yourdomain.com/deploy.php
Deploy: Click Execute Automated Deployment.

Configure Rules: Edit restricted_ips.txt to add your target IP ranges or segments (one per line).

Set Passcode: Open verify.php in a text editor and update your custom secure access passcode.

🔒 Security Cleanup: Delete the deployment script (setup-ip-restriction.php) from your server immediately after installation.
