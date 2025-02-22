# SecurityGuard PHP Class

## Overview

`SecurityGuard` is a PHP class designed to enhance the security of web applications by implementing various protective mechanisms. It provides features such as rate limiting, IP and country blocking, bot detection, CSRF protection, proxy detection, and secure logging. The class supports multiple storage backends (Session, Redis, SQLite, MySQL) and includes advanced features like Token Bucket rate limiting and database-backed logging.

### Key Features
- **Rate Limiting**: Limits requests per second, minute, hour, and day using both traditional counting and Token Bucket algorithms.
- **IP Blocking**: Blocks specific IPs or detects and blocks requests from proxies.
- **Country Blocking**: Blocks requests from specified countries using GeoIP2.
- **Bot Detection**: Identifies bots by checking open ports (e.g., 80, 443).
- **CSRF Protection**: Implements CSRF token validation.
- **CORS Support**: Configurable Cross-Origin Resource Sharing headers.
- **Secure Logging**: Logs events in a SQLite database with automatic cleanup.
- **XSS, SQL Injection, and Session Hijacking Protection**: Built-in sanitization and secure headers.

## Requirements
- PHP 7.4+
- Composer for dependency management
- Required PHP extensions: `pdo_sqlite`, `redis` (optional for Redis storage)
- GeoIP2 library: `composer require geoip2/geoip2`
- GeoLite2 Country database: Download from [MaxMind](https://dev.maxmind.com/geoip/geolite2-free-geolocation-data) and place in `/geoip/GeoLite2-Country.mmdb`

## Installation
1. Clone or download the repository:
    ```bash
    git clone <repository-url>
    cd <repository-directory>
    ```
2. Install dependencies via Composer:
    ```bash
    composer require geoip2/geoip2
    ```
3. Place the GeoLite2 Country database in the `/geoip/` directory:
    ```bash
    mkdir geoip
    mv GeoLite2-Country.mmdb geoip/
    ```
4. Ensure the web server has write permissions for `/cache/` and `/logs/` directories:
    ```bash
    chmod -R 777 cache logs
    ```
## Usage
### Basic Usage

Create an instance of `SecurityGuard` and call `checkRequest()` to validate incoming requests:
```php
<?php
require 'vendor/autoload.php';

$security = new SecurityGuard([
    'blockedIps' => ['192.168.1.1'],
    'enableCsrf' => false // Disable CSRF for CLI testing
]);

if ($security->checkRequest()) {
    // Request blocked
    exit;
}
echo "Request allowed!";
```

### Configuration Options
The constructor accepts an associative array with the following options:

| Option             | Type    | Default Value       | Description                                      |
|--------------------|---------|---------------------|--------------------------------------------------|
| `blockedIps`      | array   | `[]`                | List of IPs to block                             |
| `blockedCountries`| array   | `[]`                | List of country codes (e.g., `['IR', 'US']`)     |
| `limits`          | array   | See `$limits` above | Request limits per time period                   |
| `storageType`     | string  | `'session'`         | Storage backend (`session`, `redis`, `sqlite`, `mysql`) |
| `storageConfig`   | array   | `[]`                | Config for storage (e.g., host, port, dbname)    |
| `corsOptions`     | array   | See `$corsOptions`  | CORS settings                                    |
| `enableCsrf`      | bool    | `true`              | Enable/disable CSRF protection                   |

### Example with CSRF and Proxy Detection
```php
$security = new SecurityGuard([
    'corsOptions' => ['allowedOrigins' => ['http://localhost']],
    'enableCsrf' => true
]);

// Get CSRF token for client-side use
$csrfToken = $security->getCsrfToken();
echo "CSRF Token: $csrfToken\n";

// Simulate a request with CSRF token and proxy header
$_SERVER['HTTP_X_CSRF_TOKEN'] = $csrfToken;
$_SERVER['HTTP_X_FORWARDED_FOR'] = '192.168.1.1, 10.0.0.1';

if ($security->checkRequest()) {
    exit; // Blocked due to proxy or other checks
}
echo "Request allowed!";
```

### Running Tests
The file includes built-in tests for various features. Run it in CLI:
```php
php phpsecurity.php
```

Expected output includes results for IP blocking, country blocking, rate limiting, bot detection, and proxy detection.

### Security Features
- SQL Injection: Uses prepared statements for all database queries.
- XSS: Sanitizes inputs and outputs with htmlspecialchars.
- Session Hijacking: Enforces HttpOnly and Secure cookies.
- CSRF: Validates requests with a unique token.
- Proxy Detection: Blocks requests with proxy headers like X-Forwarded-For.
- Rate Limiting: Combines traditional limits with Token Bucket algorithm.

### Logging
Events are logged in a SQLite database (`security_logs.db`) in the `/logs/` directory. Logs older than 30 days are automatically deleted. To view logs: