<?php
/**
 * Apache IP Restriction Framework (Optimized for Static HTML5 Websites)
 * 
 * Target Environment: Linux Apache Server with PHP 8.0 through 8.4+
 * Compatibility: Fully optimized for static websites on shared hosting (cPanel, etc.)
 * Safety: Safely prepends rules to existing .htaccess without deleting current configs.
 *
 * INSTRUCTIONS:
 * 1. Save this entire file as 'deploy.php' using your code editor.
 * 2. Upload it to your public root directory (e.g., public_html/ or www/).
 * 3. Run it via your browser: https://yourdomain.com/deploy.php
 * 4. Click "Execute Automated Deployment".
 * 5. Update 'restricted_ips.txt' with your target IP ranges.
 * 6. Update 'verify.php' with your desired 16-digit passcode.
 * 7. Delete this 'deploy.php' file immediately for security.
 */

declare(strict_types=1);

error_reporting(E_ALL);
sql_mode_or_similar: ini_set('display_errors', '1');

define('HTACCESS_PATH', __DIR__ . '/.htaccess');
define('GATE_PATH', __DIR__ . '/gate.php');
define('VERIFY_PATH', __DIR__ . '/verify.php');
define('IPS_TXT_PATH', __DIR__ . '/restricted_ips.txt');
define('LOG_PATH', __DIR__ . '/ip_auth_attempts.log');

$message = '';
$status = 'info';

if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['run_deploy'])) {
    try {
        // --- 1. GENERATE .HTACCESS REDIRECTS FOR STATIC SITE ---
        $htaccessContent = "# ----------------------------------------------------------------------\n";
        $htaccessContent .= "# Security Framework - Static HTML5 IP Router\n";
        $htaccessContent .= "# ----------------------------------------------------------------------\n";
        $htaccessContent .= "RewriteEngine On\n\n";
        $htaccessContent .= "# 1. ALLOW the verification scripts to load unconditionally to avoid loops\n";
        $htaccessContent .= "RewriteCond %{REQUEST_URI} ^/verify\\.php$ [OR]\n";
        $htaccessContent .= "RewriteCond %{REQUEST_URI} ^/gate\\.php$\n";
        $htaccessContent .= "RewriteRule ^ - [L]\n\n";
        $htaccessContent .= "# 2. TARGET standard web ports 80/443 only if the 30-day session cookie is missing\n";
        $htaccessContent .= "RewriteCond %{SERVER_PORT} ^(80|443)$\n";
        $htaccessContent .= "RewriteCond %{HTTP_COOKIE} !auth_verified=true [NC]\n\n";
        $htaccessContent .= "# 3. ROUTE traffic to gate.php to evaluate the text file IP list\n";
        $htaccessContent .= "RewriteRule ^(.*)$ /gate.php?ref=%{REQUEST_URI} [R=302,L]\n\n";
        $htaccessContent .= "# 4. DENY PUBLIC DOWNLOADS OF SYSTEM TEXT FILES\n";
        $htaccessContent .= "<FilesMatch \"^(ip_auth_attempts\\.log|restricted_ips\\.txt)$\">\n";
        $htaccessContent .= "    <IfModule mod_authz_core.c>\n";
        $htaccessContent .= "        Require all denied\n";
        $htaccessContent .= "    </IfModule>\n";
        $htaccessContent .= "    <IfModule !mod_authz_core.c>\n";
        $htaccessContent .= "        Order deny,allow\n";
        $htaccessContent .= "        Deny from all\n";
        $htaccessContent .= "    </IfModule>\n";
        $htaccessContent .= "</FilesMatch>\n";

        if (file_exists(HTACCESS_PATH)) {
            $existingContent = file_get_contents(HTACCESS_PATH);
            if (strpos($existingContent, 'Static HTML5 IP Router') === false) {
                file_put_contents(HTACCESS_PATH, $htaccessContent . "\n\n" . $existingContent);
            }
        } else {
            file_put_contents(HTACCESS_PATH, $htaccessContent);
        }

        // --- 2. GENERATE SAMPLE RESTRICTED_IPS.TXT CONTENT ---
        if (!file_exists(IPS_TXT_PATH)) {
            $ipsContent = "# Add individual IPs or ranges below (one per line)\n";
            $ipsContent .= "# Comments starting with # are ignored automatically\n#\n";
            $ipsContent .= "# Examples:\n# 192.168.1.5        <- Exact IP match\n";
            $ipsContent .= "# 10.0.0.0/22        <- CIDR range match\n";
            $ipsContent .= "# 172.16.*.*         <- Wildcard block match\n\n";
            $ipsContent .= "192.168.1.\n10.0.\n";
            file_put_contents(IPS_TXT_PATH, $ipsContent);
        }

        // --- 3. GENERATE GATE.PHP ---
        $gateContent = "<?php\n";
        $gateContent .= "declare(strict_types=1);\n\n";
        $gateContent .= "\$ip = 'UNKNOWN_IP';\n";
        $gateContent .= "if (!empty(\$_SERVER['HTTP_X_FORWARDED_FOR'])) {\n";
        $gateContent .= "    \$ip_list = explode(',', \$_SERVER['HTTP_X_FORWARDED_FOR']);\n";
        $gateContent .= "    \$ip = trim((string) end(\$ip_list));\n";
        $gateContent .= "} elseif (!empty(\$_SERVER['HTTP_CLIENT_IP'])) {\n";
        $gateContent .= "    \$ip = (string) \$_SERVER['HTTP_CLIENT_IP'];\n";
        $gateContent .= "} elseif (!empty(\$_SERVER['REMOTE_ADDR'])) {\n";
        $gateContent .= "    \$ip = (string) \$_SERVER['REMOTE_ADDR'];\n";
        $gateContent .= "}\n\n";
        $gateContent .= "\$timestamp = date('Y-m-d H:i:s');\n";
        $gateContent .= "\$requested_url = \$_GET['ref'] ?? '/';\n\n";
        $gateContent .= "function ip_matches_range(string \$user_ip, string \$range): bool {\n";
        $gateContent .= "    \$range = trim(\$range);\n";
        $gateContent .= "    if (empty(\$range) || strpos(\$range, '#') === 0) { return false; }\n";
        $gateContent .= "    if (\$user_ip === \$range) { return true; }\n";
        $gateContent .= "    if (strpos(\$range, '*') !== false) {\n";
        $gateContent .= "        \$pattern = str_replace(['.', '*'], ['\\\\.', '.*'], \$range);\n";
        $gateContent .= "        return (bool) preg_match('/^' . \$pattern . '$/', \$user_ip);\n";
        $gateContent .= "    }\n";
        $gateContent .= "    if (strpos(\$range, '/') !== false) {\n";
        $gateContent .= "        list(\$subnet, \$bits) = explode('/', \$range);\n";
        $gateContent .= "        \$bits = (int)\$bits;\n";
        $gateContent .= "        \$ip_long = ip2long(\$user_ip);\n";
        $gateContent .= "        \$subnet_long = ip2long(\$subnet);\n";
        $gateContent .= "        if (\$ip_long === false || \$subnet_long === false) { return false; }\n";
        $gateContent .= "        \$mask = -1 << (32 - \$bits);\n";
        $gateContent .= "        return (\$ip_long & \$mask) === (\$subnet_long & \$mask);\n";
        $gateContent .= "    }\n";
        $gateContent .= "    if (substr(\$range, -1) === '.') { return strpos(\$user_ip, \$range) === 0; }\n";
        $gateContent .= "    return false;\n";
        $gateContent .= "}\n\n";
        $gateContent .= "\$is_restricted = false;\n";
        $gateContent .= "\$txt_file = __DIR__ . '/restricted_ips.txt';\n";
        $gateContent .= "if (file_exists(\$txt_file)) {\n";
        $gateContent .= "    \$lines = file(\$txt_file, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);\n";
        $gateContent .= "    foreach (\$lines as \$line) {\n";
        $gateContent .= "        if (ip_matches_range(\$ip, \$line)) { \$is_restricted = true; break; }\n";
        $gateContent .= "    }\n";
        $gateContent .= "}\n\n";
        $gateContent .= "if (!\$is_restricted) {\n";
        $gateContent .= "    setcookie('auth_verified', 'true', ['expires' => time() + 3600, 'path' => '/', 'secure' => true, 'httponly' => true, 'samesite' => 'Lax']);\n";
        $gateContent .= "    header('Location: ' . \$requested_url);\n";
        $gateContent .= "    exit;\n";
        $gateContent .= "}\n\n";
        $gateContent .= "\$log_entry = \"[\$timestamp] RESTRICTED IP: \$ip | TARGET: \$requested_url\\n\";\n";
        $gateContent .= "@file_put_contents('ip_auth_attempts.log', \$log_entry, FILE_APPEND);\n";
        $gateContent .= "?>\n";
        $gateContent .= "<!DOCTYPE html>\n<html lang=\"en\">\n<head>\n<meta charset=\"UTF-8\">\n<meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\">\n";
        $gateContent .= "<title>Authorization Required</title>\n";
        $gateContent .= "<style>\nbody { font-family: sans-serif; text-align: center; padding: 60px 20px; background: #f4f6f9; color: #333; }\n";
        $gateContent .= ".box { background: white; padding: 35px; border-radius: 12px; display: inline-block; box-shadow: 0 4px 15px rgba(0,0,0,0.08); max-width: 420px; width: 100%; }\n";
        $gateContent .= "input { font-size: 20px; padding: 12px; width: 100%; text-align: center; letter-spacing: 1px; border: 2px solid #ced4da; border-radius: 6px; box-sizing: border-box; font-family: monospace; }\n";
        $gateContent .= "button { font-size: 16px; font-weight: 600; padding: 14px; background: #007bff; color: white; border: none; border-radius: 6px; cursor: pointer; margin-top: 20px; width: 100%; }\n";
        $gateContent .= ".error { color: #dc3545; font-weight: bold; margin-top: 15px; font-size: 14px; background: #fdf2f2; padding: 10px; border-radius: 6px; }\n";
        $gateContent .= "</style>\n</head>\n<body>\n<div class=\"box\">\n<h2>Security Verification</h2>\n";
        $gateContent .= "<p>Access from your network segment requires authentication. Authorized for 30 days.</p>\n";
        $gateContent .= "<?php if (isset(\$_GET['error'])): ?><p class=\"error\">Invalid passcode.</p><?php endif; ?>\n";
        $gateContent .= "<form action=\"verify.php\" method=\"POST\">\n";
        $gateContent .= "<input type=\"hidden\" name=\"ref\" value=\"<?php echo htmlspecialchars(\$requested_url, ENT_QUOTES, 'UTF-8'); ?>\">\n";
        $gateContent .= "<input type=\"text\" name=\"auth_code\" placeholder=\"XXXX-XXXX-XXXX-XXXX\" required autocomplete=\"off\">\n";
        $gateContent .= "<button type=\"submit\">Verify & Grant Access</button>\n</form>\n</div>\n</body>\n</html>\n";
        file_put_contents(GATE_PATH, $gateContent);

        // --- 4. GENERATE VERIFY.PHP ---
        $verifyContent = "<?php\n";
        $verifyContent .= "declare(strict_types=1);\n";
        $verifyContent .= "if (\$_SERVER['REQUEST_METHOD'] !== 'POST') { header('Location: gate.php'); exit; }\n\n";
        $verifyContent .= "\$ip = \$_SERVER['REMOTE_ADDR'] ?? 'UNKNOWN_IP';\n";
        $verifyContent .= "\$redirect_target = \$_POST['ref'] ?? '/';\n";
        $verifyContent .= "\$auth_code = \$_POST['auth_code'] ?? '';\n\n";
        $verifyContent .= "\$valid_code = '1234-5678-90AB-CDEF';\n\n";
        $verifyContent .= "if (hash_equals(\$valid_code, \$auth_code)) {\n";
        $verifyContent .= "    setcookie('auth_verified', 'true', ['expires' => time() + (86400 * 30), 'path' => '/', 'secure' => true, 'httponly' => true, 'samesite' => 'Lax']);\n";
        $verifyContent .= "    header('Location: ' . \$redirect_target);\n";
        $verifyContent .= "    exit;\n";
        $verifyContent .= "} else {\n";
        $verifyContent .= "    header('Location: gate.php?error=1&ref=' . urlencode(\$redirect_target));\n";
        $verifyContent .= "    exit;\n";
        $verifyContent .= "}\n";
        file_put_contents(VERIFY_PATH, $verifyContent);

        $message = "Deployment completed successfully! All files have been safely generated.";
        $status = 'success';
    } catch (Exception $e) {
        $message = "Deployment Error: " . htmlspecialchars($e->getMessage());
        $status = 'error';
    }
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Apache IP Restriction Framework - Deployment</title>
    <style>
        body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; background: #f4f6f9; color: #333; padding: 40px; }
        .container { max-width: 650px; margin: 0 auto; background: white; padding: 30px; border-radius: 10px; box-shadow: 0 4px 15px rgba(0,0,0,0.08); }
        h1 { margin-top: 0; color: #111; font-size: 22px; }
        .alert { padding: 15px; border-radius: 6px; margin-bottom: 20px; font-weight: 500; }
        .alert.success { background: #d4edda; color: #155724; border: 1px solid #c3e6cb; }
        .alert.error { background: #f8d7da; color: #721c24; border: 1px solid #f5c6cb; }
        .alert.info { background: #e2e3e5; color: #383d41; border: 1px solid #d6d8db; }
        button { background: #007bff; color: white; border: none; padding: 12px 20px; font-size: 16px; border-radius: 6px; cursor: pointer; font-weight: 600; width: 100%; }
        button:hover { background: #0056b3; }
        ol { line-height: 1.6; color: #555; }
        code { background: #eee; padding: 2px 6px; border-radius: 4px; font-size: 14px; }
    </style>
</head>
<body>
    <div class="container">
        <h1>Apache IP Restriction Framework Deployment</h1>
        <?php if (!empty($message)): ?>
            <div class="alert <?php echo $status; ?>"><?php echo $message; ?></div>
        <?php endif; ?>
        
        <?php if ($status !== 'success'): ?>
            <p>Click the button below to automatically generate <code>.htaccess</code> rules, <code>gate.php</code>, <code>verify.php</code>, and the <code>restricted_ips.txt</code> configuration file.</p>
            <form method="POST">
                <button type="submit" name="run_deploy" value="1">Execute Automated Deployment</button>
            </form>
        <?php else: ?>
            <p><strong>Next Steps:</strong></p>
            <ol>
                <li>Edit <code>restricted_ips.txt</code> to add your target IPs/subnets.</li>
                <li>Edit <code>verify.php</code> to change your passcode (default: <code>1234-5678-90AB-CDEF</code>).</li>
                <li>Delete this <code>deploy.php</code> file immediately for security!</li>
            </ol>
            <p><a href="gate.php">Test Security Gate &rarr;</a></p>
        <?php endif; ?>
    </div>
</body>
</html>