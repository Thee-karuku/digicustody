<?php
/**
 * DigiCustody – 404 Not Found Page
 * Save to: /var/www/html/digicustody/404.php
 */
http_response_code(404);
?>
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1.0">
<title>404 — Page Not Found | DigiCustody</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500&family=Space+Grotesk:wght@600;700&display=swap" rel="stylesheet">
<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.0/css/all.min.css">
<style>
*{box-sizing:border-box;margin:0;padding:0;}
body{font-family:'Inter',sans-serif;background:#060d1a;color:#f0f4fa;min-height:100vh;display:flex;align-items:center;justify-content:center;padding:20px;}
.wrap{text-align:center;max-width:480px;}
.icon-wrap{width:90px;height:90px;border-radius:50%;background:rgba(201,168,76,0.1);border:2px solid rgba(201,168,76,0.2);display:flex;align-items:center;justify-content:center;margin:0 auto 28px;font-size:36px;color:#c9a84c;}
.code{font-family:'Space Grotesk',sans-serif;font-size:80px;font-weight:700;color:rgba(201,168,76,0.15);line-height:1;margin-bottom:8px;}
h1{font-family:'Space Grotesk',sans-serif;font-size:24px;font-weight:700;color:#f0f4fa;margin-bottom:10px;}
p{font-size:14px;color:#6b82a0;line-height:1.7;margin-bottom:28px;}
.btns{display:flex;gap:12px;justify-content:center;flex-wrap:wrap;}
.btn{display:inline-flex;align-items:center;gap:8px;padding:11px 22px;border-radius:10px;font-size:14px;font-weight:500;text-decoration:none;transition:all .2s;font-family:'Inter',sans-serif;}
.btn-gold{background:#c9a84c;color:#060d1a;border:none;}
.btn-gold:hover{background:#e2bc6a;transform:translateY(-1px);}
.btn-outline{background:none;border:1px solid rgba(255,255,255,0.1);color:#6b82a0;}
.btn-outline:hover{border-color:#c9a84c;color:#c9a84c;}
.logo{display:flex;align-items:center;gap:10px;justify-content:center;margin-bottom:40px;}
.logo-icon{width:34px;height:34px;border-radius:8px;background:linear-gradient(135deg,#c9a84c,#7a5010);display:flex;align-items:center;justify-content:center;font-size:14px;color:#060d1a;}
.logo-name{font-family:'Space Grotesk',sans-serif;font-size:18px;font-weight:700;color:#f0f4fa;}
.logo-name span{color:#c9a84c;}
</style>
</head>
<body>
<div class="wrap">
    <div class="logo">
        <div class="logo-icon"><i class="fas fa-shield-halved"></i></div>
        <span class="logo-name">Digi<span>Custody</span></span>
    </div>
    <div class="icon-wrap"><i class="fas fa-magnifying-glass"></i></div>
    <div class="code">404</div>
    <h1>Page Not Found</h1>
    <p>The page you are looking for doesn't exist or has been moved. Please check the URL or navigate back to the dashboard.</p>
    <div class="btns">
        <a href="/digicustody/dashboard.php" class="btn btn-gold">
            <i class="fas fa-gauge-high"></i> Go to Dashboard
        </a>
        <a href="javascript:history.back()" class="btn btn-outline">
            <i class="fas fa-arrow-left"></i> Go Back
        </a>
    </div>
</div>
</body>
</html>
