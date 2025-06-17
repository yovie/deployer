<?php
$url = 'https://your-api.example.com/deploy';
$p12File = '/path/to/client.p12';
$password = 'yourpassword';

// Initialize cURL
$ch = curl_init();

// Set cURL options
curl_setopt($ch, CURLOPT_URL, $url);
curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, true); // Verify server certificate
curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, 2); // Strict host verification

// Set P12 certificate options
curl_setopt($ch, CURLOPT_SSLCERTTYPE, 'P12');
curl_setopt($ch, CURLOPT_SSLCERT, $p12File);
curl_setopt($ch, CURLOPT_SSLCERTPASSWD, $password);

// Optional: Specify CA bundle for server verification
// curl_setopt($ch, CURLOPT_CAINFO, '/path/to/cacert.pem');

// Execute request
$response = curl_exec($ch);

// Check for errors
if (curl_errno($ch)) {
    echo 'Error: ' . curl_error($ch);
} else {
    echo $response;
}

// Close cURL session
curl_close($ch);
?>