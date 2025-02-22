<?php

require 'vendor/autoload.php'; // بارگذاری Composer

class SecurityGuard {
    private $blockedIps;
    private $blockedCountries;
    private $limits = [
        'perSecond' => 5,
        'perMinute' => 50,
        'perHour' => 200,
        'perDay' => 1000,
    ];
    private $storageType;
    private $storage;
    private $logDb;
    private $cacheDir = __DIR__ . '/cache/';
    private $logDir = __DIR__ . '/logs/';
    private $corsOptions = [
        'allowedOrigins' => ['*'],
        'allowedMethods' => ['GET', 'POST', 'OPTIONS'],
        'allowedHeaders' => ['Content-Type', 'X-CSRF-Token'],
        'maxAge' => 86400,
    ];
    private $enableCsrf;
    const REQUEST_EXPIRY = 86400;
    const TOKENS_PER_SECOND = 5;
    const BUCKET_CAPACITY = 10;

    public function __construct(array $options = []) {
        $this->blockedIps = $this->sanitizeArray($options['blockedIps'] ?? []);
        $this->blockedCountries = $this->sanitizeArray($options['blockedCountries'] ?? []);
        $this->limits = array_merge($this->limits, $this->sanitizeLimits($options['limits'] ?? []));
        $this->storageType = filter_var($options['storageType'] ?? 'session', FILTER_SANITIZE_STRING);
        $this->corsOptions = array_merge($this->corsOptions, $this->sanitizeCorsOptions($options['corsOptions'] ?? []));
        $this->enableCsrf = $options['enableCsrf'] ?? true;

        $this->ensureDirectoriesExist();
        $this->initStorage($this->sanitizeStorageConfig($options['storageConfig'] ?? []));
        $this->initLogDatabase($options['logDbConfig'] ?? $options['storageConfig'] ?? []);
        $this->handleCorsPreflight();
    }

    private function sanitizeArray(array $input): array {
        return array_map(fn($item) => htmlspecialchars(strip_tags($item), ENT_QUOTES, 'UTF-8'), $input);
    }

    private function sanitizeLimits(array $limits): array {
        return array_map(fn($value) => filter_var($value, FILTER_VALIDATE_INT, ['options' => ['min_range' => 1]]) ?: 1, $limits);
    }

    private function sanitizeCorsOptions(array $corsOptions): array {
        $sanitized = [];
        foreach ($corsOptions as $key => $value) {
            $sanitized[$key] = is_array($value) ? $this->sanitizeArray($value) : htmlspecialchars(strip_tags($value), ENT_QUOTES, 'UTF-8');
        }
        return $sanitized;
    }

    private function sanitizeStorageConfig(array $config): array {
        $sanitized = [];
        foreach ($config as $key => $value) {
            $sanitized[$key] = htmlspecialchars(strip_tags($value), ENT_QUOTES, 'UTF-8');
        }
        return $sanitized;
    }

    private function ensureDirectoriesExist(): void {
        foreach ([$this->cacheDir, $this->logDir] as $dir) {
            if (!is_dir($dir)) mkdir($dir, 0777, true);
        }
    }

    private function handleCorsPreflight(): void {
        if (isset($_SERVER['REQUEST_METHOD']) && $_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
            $this->setSecureHeaders();
            $this->setCorsHeaders();
            http_response_code(204);
            exit;
        }
    }

    private function setSecureHeaders(): void {
        header("X-Content-Type-Options: nosniff");
        header("X-Frame-Options: DENY");
        header("X-XSS-Protection: 1; mode=block");
        header("Content-Security-Policy: default-src 'self'");
    }

    private function setCorsHeaders(): void {
        $cors = $this->corsOptions;
        header("Access-Control-Allow-Origin: " . implode(', ', $cors['allowedOrigins']));
        header("Access-Control-Allow-Methods: " . implode(', ', $cors['allowedMethods']));
        header("Access-Control-Allow-Headers: " . implode(', ', $cors['allowedHeaders']));
        header("Access-Control-Max-Age: {$cors['maxAge']}");
    }

    private function initStorage(array $config): void {
        switch ($this->storageType) {
            case 'session':
                $this->startSession();
                $this->storage = &$_SESSION['requestLog'];
                break;

            case 'redis':
                $this->storage = new Redis();
                $this->storage->connect($config['host'] ?? '127.0.0.1', $config['port'] ?? 6379);
                break;

            case 'sqlite':
                $this->storage = new PDO('sqlite:' . ($config['path'] ?? __DIR__ . '/security.db'));
                $this->initDatabase('sqlite');
                break;

            case 'mysql':
                $dsn = "mysql:host=" . ($config['host'] ?? 'localhost') . ";dbname=" . ($config['dbname'] ?? 'security');
                $this->storage = new PDO($dsn, $config['username'] ?? 'root', $config['password'] ?? '');
                $this->initDatabase('mysql');
                break;

            default:
                throw new Exception("نوع ذخیره‌سازی نامعتبر: $this->storageType");
        }
    }

    private function startSession(): void {
        if (session_status() === PHP_SESSION_NONE) {
            ini_set('session.use_only_cookies', 1);
            ini_set('session.cookie_httponly', 1);
            ini_set('session.cookie_secure', 1);
            session_start([
                'cookie_lifetime' => 86400,
                'gc_maxlifetime' => 86400,
            ]);
            if (!isset($_SESSION['csrf_token'])) {
                $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
            }
        }
        if (!isset($_SESSION['requestLog'])) {
            $_SESSION['requestLog'] = [];
        }
        if (!isset($_SESSION['tokenBucket'])) {
            $_SESSION['tokenBucket'] = ['tokens' => self::BUCKET_CAPACITY, 'lastRefill' => microtime(true)];
        }
    }

    private function initDatabase(string $type): void {
        $this->storage->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
        $idType = $type === 'sqlite' ? 'INTEGER PRIMARY KEY AUTOINCREMENT' : 'INT AUTO_INCREMENT PRIMARY KEY';
        $this->storage->exec("
            CREATE TABLE IF NOT EXISTS requests (
                id $idType,
                ip VARCHAR(45) NOT NULL,
                timestamp DOUBLE NOT NULL,
                INDEX idx_ip_timestamp (ip, timestamp)
            );
        ");
    }

    private function initLogDatabase(array $config): void {
        $this->logDb = new PDO('sqlite:' . ($config['path'] ?? __DIR__ . '/logs/security_logs.db'));
        $this->logDb->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
        $this->logDb->exec("
            CREATE TABLE IF NOT EXISTS logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp DATETIME NOT NULL,
                ip VARCHAR(45) NOT NULL,
                message TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_timestamp ON logs (timestamp);
        ");
    }

    public function checkRequest(): bool {
        $ip = $this->getClientIp();
        $currentTime = microtime(true);

        $this->setSecureHeaders();
        $this->setCorsHeaders();

        if ($this->enableCsrf && !$this->verifyCsrfToken()) {
            $this->blockResponse("توکن CSRF نامعتبر است.");
            return true;
        }

        if ($this->isProxyUsed()) {
            $this->blockResponse("استفاده از پروکسی تشخیص داده شد.");
            return true;
        }

        if ($this->isIpBlocked($ip)) {
            $this->blockResponse("IP شما بلاک شده است.");
            return true;
        }

        if ($this->isCountryBlocked($ip)) {
            $this->blockResponse("درخواست از کشور شما بلاک شده است.");
            return true;
        }

        if ($this->isBotByPortCheck($ip)) {
            $this->blockResponse("درخواست شما به‌عنوان ربات شناسایی شد.");
            return true;
        }

        if (!$this->checkTokenBucket($ip, $currentTime)) {
            $this->blockResponse("محدودیت نرخ درخواست با Token Bucket نقض شد.");
            return true;
        }

        $limitsExceeded = $this->checkAllLimits($ip, $currentTime);
        if ($limitsExceeded) {
            $this->blockResponse($limitsExceeded);
            return true;
        }

        $this->logRequest($ip, $currentTime);
        return false;
    }

    /**
     * تشخیص استفاده از پروکسی در هر لایه IP
     * @return bool
     */
    private function isProxyUsed(): bool {
        $proxyHeaders = [
            'HTTP_X_FORWARDED_FOR', // چندین IP ممکنه اینجا باشه
            'HTTP_VIA',            // وجودش نشون‌دهنده پروکسیه
            'HTTP_X_PROXY_ID',     // پروکسی‌های خاص
            'HTTP_PROXY_CONNECTION'
        ];

        foreach ($proxyHeaders as $header) {
            if (isset($_SERVER[$header])) {
                $value = $_SERVER[$header];
                $this->logEvent("پروکسی تشخیص داده شد با هدر $header: $value");

                // چک کردن لایه‌های IP توی X-Forwarded-For
                if ($header === 'HTTP_X_FORWARDED_FOR') {
                    $ips = explode(',', $value);
                    if (count($ips) > 1) { // بیش از یک IP = پروکسی
                        $this->logEvent("چندین IP در X-Forwarded-For: $value");
                        return true;
                    }
                }
                return true; // وجود هر کدوم از هدرها = پروکسی
            }
        }
        return false;
    }

    public function getCsrfToken(): string {
        $this->startSession();
        return $_SESSION['csrf_token'];
    }

    private function verifyCsrfToken(): bool {
        $this->startSession();
        $token = $_SERVER['HTTP_X_CSRF_TOKEN'] ?? '';
        return hash_equals($_SESSION['csrf_token'], $token);
    }

    private function checkTokenBucket(string $ip, float $currentTime): bool {
        if ($this->storageType !== 'session') return true;

        $bucket = &$_SESSION['tokenBucket'];
        $elapsed = $currentTime - $bucket['lastRefill'];
        $newTokens = $elapsed * self::TOKENS_PER_SECOND;

        $bucket['tokens'] = min(self::BUCKET_CAPACITY, $bucket['tokens'] + $newTokens);
        $bucket['lastRefill'] = $currentTime;

        if ($bucket['tokens'] >= 1) {
            $bucket['tokens'] -= 1;
            return true;
        }
        $this->logEvent("IP $ip exceeded Token Bucket limit.");
        return false;
    }

    private function isBotByPortCheck(string $ip): bool {
        $portsToCheck = [80, 443, 22, 23];
        $timeout = 1;

        foreach ($portsToCheck as $port) {
            if ($connection = @fsockopen($ip, $port, $errno, $errstr, $timeout)) {
                fclose($connection);
                $this->logEvent("IP $ip به‌عنوان ربات تشخیص داده شد (پورت $port پاسخگو).");
                return true;
            }
        }
        return false;
    }

    private function checkAllLimits(string $ip, float $currentTime): ?string {
        $intervals = [
            'perSecond' => 1,
            'perMinute' => 60,
            'perHour' => 3600,
            'perDay' => self::REQUEST_EXPIRY
        ];

        foreach ($intervals as $key => $seconds) {
            $count = $this->getRequestCount($ip, $currentTime, $seconds);
            if ($count >= $this->limits[$key]) {
                $this->logEvent("IP $ip exceeded $key limit: $count");
                return "محدودیت درخواست در $key نقض شد (تعداد: $count)";
            }
        }
        return null;
    }

    private function getRequestCount(string $ip, float $currentTime, int $seconds): int {
        switch ($this->storageType) {
            case 'session':
                $times = $this->storage[$ip] ?? [];
                return count(array_filter($times, fn($time) => ($currentTime - $time) <= $seconds));

            case 'redis':
                $key = "requests:$ip:$seconds";
                $this->storage->lTrim($key, -1000, -1);
                $times = $this->storage->lRange($key, 0, -1);
                return count(array_filter($times, fn($time) => ($currentTime - $time) <= $seconds));

            case 'sqlite':
            case 'mysql':
                $stmt = $this->storage->prepare("SELECT COUNT(*) FROM requests WHERE ip = :ip AND timestamp > :startTime");
                $stmt->execute([':ip' => $ip, ':startTime' => $currentTime - $seconds]);
                return (int)$stmt->fetchColumn();
        }
        return 0;
    }

    private function logRequest(string $ip, float $time): void {
        switch ($this->storageType) {
            case 'session':
                $this->storage[$ip] = $this->storage[$ip] ?? [];
                $this->storage[$ip][] = $time;
                $this->storage[$ip] = array_filter($this->storage[$ip], fn($t) => ($time - $t) <= self::REQUEST_EXPIRY);
                break;

            case 'redis':
                $intervals = [1, 60, 3600, self::REQUEST_EXPIRY];
                foreach ($intervals as $ttl) {
                    $key = "requests:$ip:$ttl";
                    $this->storage->rPush($key, $time);
                    $this->storage->expire($key, $ttl);
                }
                break;

            case 'sqlite':
            case 'mysql':
                $stmt = $this->storage->prepare("INSERT INTO requests (ip, timestamp) VALUES (:ip, :time)");
                $stmt->execute([':ip' => $ip, ':time' => $time]);
                $this->storage->exec("DELETE FROM requests WHERE timestamp < " . (microtime(true) - self::REQUEST_EXPIRY));
                break;
        }
    }

    public function blockIp(string $ip): void {
        if (!in_array($ip, $this->blockedIps)) {
            $this->blockedIps[] = filter_var($ip, FILTER_VALIDATE_IP) ?: $ip;
        }
    }

    public function blockCountry(string $countryCode): void {
        $countryCode = strtoupper(filter_var($countryCode, FILTER_SANITIZE_STRING));
        if (!in_array($countryCode, $this->blockedCountries)) {
            $this->blockedCountries[] = $countryCode;
        }
    }

    private function getClientIp(): string {
        $ip = $_SERVER['HTTP_X_FORWARDED_FOR'] ?? $_SERVER['REMOTE_ADDR'] ?? 'unknown';
        return filter_var($ip, FILTER_VALIDATE_IP) ?: 'unknown';
    }

    private function isIpBlocked(string $ip): bool {
        return in_array($ip, $this->blockedIps);
    }

    private function isCountryBlocked(string $ip): bool {
        if (empty($this->blockedCountries)) return false;
        $countryCode = $this->getCountryCode($ip);
        return in_array($countryCode, $this->blockedCountries);
    }

    private function getCountryCode(string $ip): ?string {
        $databaseFile = __DIR__ . '/geoip/GeoLite2-Country.mmdb';
        if (!file_exists($databaseFile)) {
            $this->logEvent("GeoIP database file not found: $databaseFile");
            return null;
        }

        try {
            $reader = new \GeoIp2\Database\Reader($databaseFile);
            $record = $reader->country($ip);
            return $record->country->isoCode ?? null;
        } catch (\GeoIp2\Exception\AddressNotFoundException $e) {
            $this->logEvent("IP $ip not found in GeoIP database.");
            return null;
        } catch (Exception $e) {
            $this->logEvent("GeoIP error: " . $e->getMessage());
            return null;
        }
    }

    private function logEvent(string $message): void {
        $timestamp = date('Y-m-d H:i:s');
        $ip = $this->getClientIp();
        $stmt = $this->logDb->prepare("INSERT INTO logs (timestamp, ip, message) VALUES (:timestamp, :ip, :message)");
        $stmt->execute([
            ':timestamp' => $timestamp,
            ':ip' => $ip,
            ':message' => htmlspecialchars($message, ENT_QUOTES, 'UTF-8')
        ]);
        $this->logDb->exec("DELETE FROM logs WHERE timestamp < DATETIME('now', '-30 days')");
    }

    private function blockResponse(string $message): void {
        $this->setSecureHeaders();
        $this->setCorsHeaders();
        http_response_code(403);
        header('Content-Type: text/plain; charset=utf-8');
        exit(htmlspecialchars($message, ENT_QUOTES, 'UTF-8'));
    }
}

// تست‌ها با بافر خروجی
ob_start();

$security = new SecurityGuard([
    'corsOptions' => ['allowedOrigins' => ['http://localhost']],
    'limits' => ['perSecond' => 2],
    'enableCsrf' => false
]);

echo "توکن CSRF: " . $security->getCsrfToken() . "\n";
echo "------------\n";

echo "تست بلاک IP:\n";
$security->blockIp('127.0.0.1');
echo $security->checkRequest() ? "درخواست بلاک شد (IP)\n" : "درخواست مجاز است\n";
echo "------------\n";

echo "تست بلاک کشور:\n";
$security = new SecurityGuard(['blockedCountries' => ['IR'], 'enableCsrf' => false]);
echo $security->checkRequest() ? "درخواست بلاک شد (کشور)\n" : "درخواست مجاز است\n";
echo "------------\n";

echo "تست محدودیت نرخ و Token Bucket (Session):\n";
$security = new SecurityGuard(['storageType' => 'session', 'limits' => ['perSecond' => 2], 'enableCsrf' => false]);
for ($i = 0; $i < 5; $i++) {
    echo "درخواست $i " . ($security->checkRequest() ? "بلاک شد (نرخ/Token)\n" : "مجاز است\n");
    usleep(100000);
}
echo "------------\n";

echo "تست تشخیص ربات:\n";
$security = new SecurityGuard(['enableCsrf' => false]);
echo $security->checkRequest() ? "درخواست بلاک شد (ربات)\n" : "درخواست مجاز است (انسان)\n";
echo "------------\n";

echo "تست با SQLite و لاگ دیتابیس:\n";
$security = new SecurityGuard([
    'storageType' => 'sqlite',
    'storageConfig' => ['path' => __DIR__ . '/security.db'],
    'limits' => ['perSecond' => 3],
    'enableCsrf' => false
]);
for ($i = 0; $i < 5; $i++) {
    echo "درخواست $i " . ($security->checkRequest() ? "بلاک شد (SQLite)\n" : "مجاز است\n");
    usleep(100000);
}

// تست پروکسی (شبیه‌سازی هدر پروکسی)
echo "------------\n";
echo "تست تشخیص پروکسی:\n";
$_SERVER['HTTP_X_FORWARDED_FOR'] = '192.168.1.1, 10.0.0.1'; // شبیه‌سازی پروکسی
$security = new SecurityGuard(['enableCsrf' => false]);
echo $security->checkRequest() ? "درخواست بلاک شد (پروکسی)\n" : "درخواست مجاز است\n";

ob_end_flush();