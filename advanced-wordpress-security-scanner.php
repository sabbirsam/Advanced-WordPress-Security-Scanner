<?php
/*
Plugin Name: Advanced WordPress Security Scanner
Plugin URI: https://example.com/advanced-security-scanner
Description: Comprehensive WordPress security scanning with detailed dashboard and history tracking
Version: 1.0
Author: sabbirsam
*/

class AdvancedWordPressSecurityScanner {

    private $batch_size = 5000;
    private $scan_session_key = 'wps_current_scan_session';


    private $scan_history_option = 'wps_security_scan_history';
    private $scan_log = [];
    private $exclusion_option = 'wps_security_scan_exclusions';

    public function __construct() {
        add_action('admin_menu', [$this, 'add_security_scanner_menu']);
        add_action('admin_enqueue_scripts', [$this, 'enqueue_admin_scripts']);



        add_action('wp_ajax_run_security_scan', [$this, 'run_security_scan']);
        add_action('wp_ajax_get_scan_history', [$this, 'get_scan_history']);
        add_action('wp_ajax_get_specific_scan_details', [$this, 'get_specific_scan_details']); 
        add_action('wp_ajax_update_scan_exclusions', [$this, 'update_scan_exclusions']);
    }

    public function enqueue_admin_scripts() {
        wp_enqueue_script('jquery');
        wp_enqueue_script('security-scanner-script', plugin_dir_url(__FILE__) . 'js/scanner.js', ['jquery'], '1.1', true);
        wp_enqueue_style('security-scanner-style', plugin_dir_url(__FILE__) . 'css/scanner.css');
        wp_localize_script('security-scanner-script', 'appLocalizer', [
            'ajax_url' => admin_url('admin-ajax.php'),
            'nonce' => wp_create_nonce('wp_rest')
        ]);
    }

    private $scan_paths = [
        'core' => ABSPATH,
        'wp_config' => ABSPATH . 'wp-config.php',
        'htaccess' => ABSPATH . '.htaccess',
        'uploads' => WP_CONTENT_DIR . '/uploads',
        'plugins' => WP_CONTENT_DIR . '/plugins',
        'themes' => WP_CONTENT_DIR . '/themes',
        'mu_plugins' => WP_CONTENT_DIR . '/mu-plugins',
        'wp_includes' => ABSPATH . WPINC,
        'wp_admin' => ABSPATH . 'wp-admin'
    ];

    private $core_path_mapping = [
        'wp-includes' => 'wp_includes',
        'wp-admin' => 'wp_admin',
        'wp-config.php' => 'wp_config',
        '.htaccess' => 'htaccess',
        'mu-plugins' => 'mu_plugins',
        'uploads' => 'uploads',
        'plugins' => 'plugins',
        'themes' => 'themes',
        'core' => 'core'
    ];

    private $security_patterns = [
        'dangerous_functions' => [
            // Command execution (high-risk)
            'eval(', 'system(', 'exec(', 'shell_exec(', 'passthru(', 
            'proc_open(', 'popen(', 'pcntl_exec(', 'expect_popen(',
            'assert(', 'create_function(', 'mb_ereg_replace_callback(',
            'preg_filter(', 'bzopen(', '`', // backtick operator
            
            // Process and memory manipulation (high-risk)
            'proc_nice(', 'proc_terminate(', 'proc_close(', 
            'proc_get_status(', 'proc_open(', 'leak_memory(',
            'set_time_limit(', 'ignore_user_abort(', 'memory_limit',
            'pcntl_alarm(', 'pcntl_fork(', 'pcntl_signal(',
            
            // Critical PHP functions (moderate-risk)
            'ini_alter(', 'ini_restore(', 'dl(', 'apache_setenv(',
            'ini_set(', 'mail(', 'putenv(', 'mb_send_mail(',
            'define_syslog_variables(', 'openlog(', 'syslog(',
            
            // Remote connections (monitor for unexpected usage)
            'fsockopen(', 'pfsockopen(', 'socket_create(',
            'socket_connect(', 'socket_bind(', 'socket_listen(',
            'socket_create_listen(', 'socket_create_pair(',
            'stream_socket_client(', 'stream_socket_server(',
            'ssh2_connect(', 'ftp_connect(', 'ftp_ssl_connect('
        ],
        
        'obfuscation_indicators' => [
            // Modern string manipulation and encoding
            'base64_decode', 'gzinflate', 'gzdeflate', 'gzencode', 
            'gzdecode', 'str_rot13', 'convert_uudecode', 'fromCharCode',
            'sodium_crypto_secretbox', 'openssl_encrypt', 'mcrypt_encrypt',
            'hash_hmac', 'password_hash', 'crypt',
            
            // Advanced obfuscation patterns
            '\\x[0-9a-f]{2}', // hex encoding
            '\\u[0-9a-f]{4}', // unicode encoding
            '\\[0-7]{3}', // octal encoding
            '&#x[0-9a-f]{2};', // HTML hex encoding
            '&#\d+;', // HTML decimal encoding
            '\$\{.\}', // PHP complex variable syntax
            '\$[a-zA-Z_\x7f-\xff][a-zA-Z0-9_\x7f-\xff]*\s*\(\s*\$[a-zA-Z_\x7f-\xff]',
            
            // JavaScript obfuscation
            'eval\s*\(', 'unescape\s*\(', 'String\.fromCharCode',
            'parseInt\s*\(.+?,\s*16\)', 'atob\s*\(', 'btoa\s*\(',
            'escape\s*\(', 'decodeURIComponent\s*\(', 'encodeURIComponent\s*\(',
            'Function\s*\(.*\)\s*\(', 'setTimeout\s*\(\s*function\s*\(\s*\)\s*{',
            'new\s+Function\s*\(', 'window\s*\[\s*[\'"]eval[\'"]\s*\]',
            
            // File extension obfuscation
            '\.ph(?:p[3-7]?|t|tml|ps|ar|ax|p5|p4|ar)',
            '\.(?:php|php5|php7|phtml|ph|php4|php3|php2|php1|phps|phpt|pht|phar|pgif|phtml|phtm)$',
            '\.asp(?:x|\.net)?$',
            '\.jsp(?:x|f|p)?$',
            '\.(?:sh|bash|zsh|csh|ksh|tcsh|pl|py|rb|exe|dll|scr|vbs|bat|cmd|ps1|psm1|psd1)$'
        ],
        
        'malware_signatures' => [
            // Modern malware patterns
            'eval\s*\(.*base64_decode\s*\(', 
            'eval\s*\(.*gzinflate\s*\(',
            'eval\s*\(.*str_rot13\s*\(',
            'eval\s*\(.*gzuncompress\s*\(',
            '\$GLOBALS\[\$GLOBALS',
            'preg_replace\s*\([\'"]/.*/e[\'"]',
            '(?:\\\\x[0-9a-f]{2}){4,}',
            '@include\s*[\'"]\w+://',
            'data:text/html;base64',
            'data:image/jpg;base64',
            'PHPShell', 'c99shell', 'r57shell', 'WSO shell',
            
            // Supply chain attack indicators
            'composer\.json\s+modification',
            'package\.json\s+modification',
            'vendor\/.*\/.*\.php\s+modification',
            'node_modules\/.*\/.*\.js\s+modification',
            
            // Cryptocurrency & malicious mining
            'coinhive', 'cryptonight', 'webassembly', 'wasmjit',
            'cryptoloot', 'deepminer', 'coin-hive', 'jsecoin',
            'minero', 'coinimp', 'webmine', 'monerominer',
            'cryptojacking', 'monero', 'pool.supportxmr.com',
            'xmrig', 'nanopool', 'minergate', 'nicehash',
            
            // Ransomware indicators
            '\.locked$', '\.encrypted$', '\.crypto$', '\.crypt$',
            'DECRYPT_INSTRUCTION', 'HOW_TO_DECRYPT',
            'YOUR_FILES_ARE_ENCRYPTED', 'YOUR_FILES_ARE_LOCKED',
            
            // Backdoor and remote access
            'backdoor', 'rootkit', 'webshell', 'reverse shell',
            'netcat', 'bind shell', 'reverse_tcp', 'meterpreter',
            'remote access', 'remote control', 'remoteview',
            
            // File upload vulnerabilities
            'move_uploaded_file\s*\(.*\.ph',
            'move_uploaded_file\s*\(.*\.asp',
            'move_uploaded_file\s*\(.*\.jsp',
            'move_uploaded_file\s*\(.*\.cgi',
            
            // SQL Injection attempts
            'UNION\s+SELECT', 'UNION\s+ALL\s+SELECT',
            'INSERT\s+INTO.*SELECT', 'UPDATE.*SET.*SELECT',
            'DELETE\s+FROM.*WHERE.*SELECT',
            
            // XSS patterns
            '<script.*?>.*?<\/script>', 
            'javascript:', 'vbscript:', 'livescript:',
            'onload=', 'onerror=', 'onmouseover=',
            
            // File inclusion
            'include\s*\(\s*[\'"]https?://',
            'include\s*\(\s*[\'"]ftp://',
            'require\s*\(\s*[\'"]https?://',
            'require\s*\(\s*[\'"]ftp://',
            
            // Known exploit kits
            'Angler', 'BlackHole', 'Nuclear', 'Magnitude',
            'RIG', 'Terror', 'GrandSoft', 'KaiXin',
            'Spelevo', 'Fallout', 'GreenFlash', 'Underminer'
        ],
        
        'suspicious_behaviors' => [
            // Suspicious file operations
            'fwrite\s*\(\s*\$.*\.ph',
            'file_put_contents\s*\(\s*\$.*\.ph',
            'fputs\s*\(\s*\$.*\.ph',
            
            // Network behavior
            'curl_setopt\s*\(\s*\$.*CURLOPT_URL',
            'wget\s+http', 'lynx\s+http',
            'GET\s+http', 'POST\s+http',
            
            // Database manipulation
            'DROP\s+TABLE', 'TRUNCATE\s+TABLE',
            'ALTER\s+TABLE.*DROP',
            'DELETE\s+FROM\s+wp_',
            
            // Suspicious WordPress actions
            'wp_insert_user\s*\(\s*array\s*\(',
            'wp_set_auth_cookie\s*\(\s*\$',
            'wp_set_current_user\s*\(\s*\$',
            
            // Plugin/Theme manipulation
            'activate_plugin\s*\(\s*\$',
            'switch_theme\s*\(\s*\$',
            'wp_update_plugin\s*\(\s*\$',
            
            // Option manipulation
            'update_option\s*\(\s*\$',
            'add_option\s*\(\s*\$',
            'delete_option\s*\(\s*\$'
        ]
    ];

    private $security_checks = [
        'plugin_vulnerabilities' => ['weight' => 10, 'title' => 'Plugin Vulnerability Check'],
        'wordpress_version' => ['weight' => 5, 'title' => 'WordPress Version Check'],
    ];

    public function add_security_scanner_menu() {
        add_menu_page(
            'Security Scanner', 
            'Security Scanner', 
            'manage_options', 
            'advanced-wordpress-security-scanner', 
            [$this, 'security_scanner_dashboard']
        );
    }

    public function security_scanner_dashboard() {
        $exclusions = $this->get_scan_exclusions();
       
        ?>
        <div class="wrap security-scanner-dashboard">
            <h1>Advanced WordPress Security Scanner</h1>
            <div class="scanner-controls">
                <button id="start-security-scan" class="button button-primary">Start Security Scan</button>
                <div id="scan-progress" class="scan-progress">
                    <div class="progress-bar"></div>
                    <div class="progress-text">Ready to scan</div>
                </div>
            </div>

            <div class="scan-results-container">
                <h2>Scan Results</h2>
                <div id="current-scan-results"></div>
            </div>

            <!-- Exclusion Settings -->
            <div class="exclusion-settings">
                <h2>Scan Exclusion Settings</h2>
                <form id="exclusion-settings-form">
                    <div class="exclusion-section">
                        <h3>General Exclusions</h3>
                        <div>
                            <label>Exclude Paths (one per line):</label>
                            <textarea id="exclude-paths" name="paths"><?php echo implode("\n", $exclusions['paths'] ?? []); ?></textarea>
                        </div>
                        <div>
                            <label>Exclude File Patterns (one per line):</label>
                            <textarea id="exclude-file-patterns" name="file_patterns"><?php echo implode("\n", $exclusions['file_patterns'] ?? []); ?></textarea>
                        </div>
                        <div>
                            <label>Exclude PHP Functions (one per line):</label>
                            <textarea id="exclude-functions" name="php_functions"><?php echo implode("\n", $exclusions['php_functions'] ?? []); ?></textarea>
                        </div>
                    </div>

                    <div class="exclusion-section">
                        <h3>Directory Exclusions</h3>
                        
                        <div>
                            <h4>Directories</h4>
                            <?php $this->render_directory_checkboxes('core_files', $this->get_core_file_directories(), $exclusions['core_files']); ?>
                        </div>

                        <div>
                            <h4>Plugins</h4>
                            <?php $this->render_directory_checkboxes('plugins', $this->get_installed_plugins(), $exclusions['plugins']); ?>
                        </div>

                        <div>
                            <h4>Themes</h4>
                            <?php $this->render_directory_checkboxes('themes', $this->get_installed_themes(), $exclusions['themes']); ?>
                        </div>
                    </div>

                    <button type="submit" class="button button-primary">Save Exclusions</button>
                </form>
            </div>
            
            <div class="scan-history-container">
                <h2>Scan History</h2>
                <table id="scan-history-table">
                    <thead>
                        <tr>
                            <th>Date</th>
                            <th>Status</th>
                            <th>Issues Found</th>
                            <th>Actions</th>
                        </tr>
                    </thead>
                    <tbody id="scan-history-body">
                        <!-- History will be populated via AJAX -->
                    </tbody>
                </table>
            </div>
        </div>
        <?php
    }

    
    public function get_specific_scan_details() {
        check_ajax_referer('wp_rest', 'nonce');
        $scan_index = isset($_POST['scan_index']) ? intval($_POST['scan_index']) : -1;
        $history = get_option($this->scan_history_option, []);
        if ($scan_index >= 0 && $scan_index < count($history)) {
            wp_send_json_success($history[$scan_index]);
        } else {
            wp_send_json_error('Scan details not found');
        }
    }


    public function run_security_scan() {
        check_ajax_referer('wp_rest', 'nonce');
        
        $scan_type = isset($_POST['scan_type']) ? sanitize_text_field($_POST['scan_type']) : 'initialize';
        $session_id = isset($_POST['session_id']) ? sanitize_text_field($_POST['session_id']) : null;
        
        switch ($scan_type) {
            case 'initialize':
                $response = $this->initialize_scan();
                break;
            case 'core_files':
                $response = $this->process_core_files_batch($session_id);
                break;
            case 'security_checks':
                $response = $this->process_security_checks_batch($session_id);
                break;
            case 'finalize':
                $response = $this->finalize_scan($session_id);
                break;
            default:
                wp_send_json_error('Invalid scan type');
        }
        
        wp_send_json_success($response);
    }

    private function initialize_scan() {
        $session_id = uniqid('scan_', true);
        $scan_data = [
            'session_id' => $session_id,
            'start_time' => current_time('mysql'),
            'current_path_index' => 0,
            'current_file_offset' => 0,
            'processed_files' => 0,
            'total_files' => 0,
            'current_security_check_index' => 0,
            'results' => [],
            'issues' => [],
            'completed_paths' => [],
            'completed_checks' => []
        ];
        
        // Calculate total files
        foreach ($this->scan_paths as $path) {
            if (file_exists($path)) {
                $files = $this->get_all_files($path);
                $scan_data['total_files'] += count($files);
            }
        }
        
        update_option($this->scan_session_key . '_' . $session_id, $scan_data);
        
        return [
            'type' => 'initialize',
            'session_id' => $session_id,
            'total_files' => $scan_data['total_files'],
            'total_checks' => count($this->security_checks),
            'message' => 'Scan initialized'
        ];
    }


    private function process_core_files_batch($session_id) {
        $scan_data = get_option($this->scan_session_key . '_' . $session_id);
        if (!$scan_data) {
            return ['type' => 'error', 'message' => 'Invalid session'];
        }
        
        $paths = array_keys($this->scan_paths);
        $current_path = $paths[$scan_data['current_path_index']];
        $exclusions = $this->get_scan_exclusions();

        error_log('Exclusions 1: ' . print_r($exclusions, true));

        // error_log('Processing path: ' . $current_path);
        // error_log('Exclusions: ' . print_r($exclusions, true));

        // Check if current path type is completely excluded
        if ($this->is_path_type_excluded($current_path, $exclusions)) {
            // error_log('Path excluded, skipping: ' . $current_path);
            // Skip this path entirely
            $scan_data['completed_paths'][] = $current_path;
            $scan_data['current_path_index']++;
            $scan_data['current_file_offset'] = 0;
            
            $skipped_files = count($this->get_all_files($this->scan_paths[$current_path]));
            $scan_data['processed_files'] += $skipped_files;
            
            update_option($this->scan_session_key . '_' . $session_id, $scan_data);
            
            $is_core_complete = $scan_data['current_path_index'] >= count($paths);
            $progress = ($scan_data['processed_files'] / $scan_data['total_files']) * 50;
            
            return [
                'type' => 'progress',
                'phase' => 'core_files',
                'progress' => $progress,
                'current_path' => $current_path,
                'processed_files' => $scan_data['processed_files'],
                'total_files' => $scan_data['total_files'],
                'is_complete' => $is_core_complete,
                'message' => "Skipping excluded path {$current_path}"
            ];
        }

        // Get files for current path
        $files = $this->get_all_files($this->scan_paths[$current_path]);
        $batch_end = min($scan_data['current_file_offset'] + $this->batch_size, count($files));
        
        for ($i = $scan_data['current_file_offset']; $i < $batch_end; $i++) {
            if (isset($files[$i])) {
                $file = $files[$i];
                if (!$this->should_exclude_file($file, $current_path, $exclusions)) {
                    $issues = $this->check_file_security($file, $exclusions);
                    if (!empty($issues)) {
                        $scan_data['issues'][] = [
                            'file' => $file,
                            'issues' => $issues
                        ];
                    }
                }
                $scan_data['processed_files']++;
            }
        }
        
        // Update progress
        $scan_data['current_file_offset'] = $batch_end;
        if ($batch_end >= count($files)) {
            $scan_data['completed_paths'][] = $current_path;
            $scan_data['current_path_index']++;
            $scan_data['current_file_offset'] = 0;
        }
        
        update_option($this->scan_session_key . '_' . $session_id, $scan_data);
        
        $is_core_complete = $scan_data['current_path_index'] >= count($paths);
        $progress = ($scan_data['processed_files'] / $scan_data['total_files']) * 50;
        
        return [
            'type' => 'progress',
            'phase' => 'core_files',
            'progress' => $progress,
            'current_path' => $current_path,
            'processed_files' => $scan_data['processed_files'],
            'total_files' => $scan_data['total_files'],
            'is_complete' => $is_core_complete,
            'message' => "Scanning {$current_path}"
        ];
    }

    private function is_path_type_excluded($path_type, $exclusions) {
        // First, map the path type to its correct exclusion identifier
        $mapped_path = $path_type;

        // Convert path_type to the format used in exclusions if needed
        foreach ($this->core_path_mapping as $exclusion_key => $scan_key) {
            if ($path_type === $scan_key) {
                $mapped_path = $exclusion_key;
                break;
            }
        }
        
        // error_log('Mapped path: ' . $mapped_path);

        // Check if the path is excluded
        if (!empty($exclusions['core_files']) && in_array($mapped_path, $exclusions['core_files'])) {
            // error_log('Path is excluded: ' . $mapped_path);
            return true;
        }

        // Special handling for plugins and themes directories
        switch ($path_type) {
            case 'plugins':
                if (!empty($exclusions['core_files']) && in_array('plugins', $exclusions['core_files'])) {
                    return true;
                }
                break;
            case 'themes':
                if (!empty($exclusions['core_files']) && in_array('themes', $exclusions['core_files'])) {
                    return true;
                }
                break;
        }

        // error_log('Path is not excluded: ' . $mapped_path);
        return false;
    }

    private function should_exclude_file($file, $current_path, $exclusions) {

        if (!empty($exclusions['core_files'])) {
            foreach ($exclusions['core_files'] as $excluded_dir) {
                // Map the excluded directory to its scan path
                $mapped_dir = $this->core_path_mapping[$excluded_dir] ?? $excluded_dir;
                
                if (isset($this->scan_paths[$mapped_dir])) {
                    $dir_path = $this->scan_paths[$mapped_dir];
                    if (strpos($file, $dir_path) === 0) {
                        // error_log('File excluded due to core directory exclusion: ' . $excluded_dir);
                        return true;
                    }
                }
            }
        }

        // Check if file matches any exclusion patterns
        if (!empty($exclusions['file_patterns'])) {
            foreach ($exclusions['file_patterns'] as $pattern) {
                $pattern = trim($pattern);
                if (!empty($pattern)) {
                    // Support both glob and regex patterns
                    if ($this->is_regex_pattern($pattern)) {
                        // For regex patterns
                        if (@preg_match($pattern, $file)) {
                            // error_log('File excluded due to regex pattern: ' . $pattern);
                            return true;
                        }
                    } else {
                        // For glob patterns
                        if (fnmatch($pattern, $file)) {
                            // error_log('File excluded due to glob pattern: ' . $pattern);
                            return true;
                        }
                    }
                }
            }
        }

        // Check if file is in excluded paths
        if (!empty($exclusions['paths'])) {
            foreach ($exclusions['paths'] as $path) {
                $path = trim($path);
                if (!empty($path)) {
                    // Convert relative paths to absolute
                    if (strpos($path, '/') !== 0) {
                        $path = ABSPATH . $path;
                    }
                    
                    // Normalize paths for comparison
                    $path = wp_normalize_path($path);
                    $normalized_file = wp_normalize_path($file);
                    
                    if (strpos($normalized_file, $path) === 0) {
                        // error_log('File excluded due to custom path: ' . $path);
                        return true;
                    }
                }
            }
        }

        // Handle plugin-specific exclusions
        if ($current_path === 'plugins' && !empty($exclusions['plugins'])) {
            foreach ($exclusions['plugins'] as $plugin) {
                $plugin = trim($plugin);
                if (!empty($plugin)) {
                    $plugin_path = WP_CONTENT_DIR . '/plugins/' . $plugin;
                    $plugin_path = wp_normalize_path($plugin_path);
                    $normalized_file = wp_normalize_path($file);
                    
                    if (strpos($normalized_file, $plugin_path) === 0) {
                        // error_log('File excluded due to plugin exclusion: ' . $plugin);
                        return true;
                    }
                }
            }
        }

        // Handle theme-specific exclusions
        if ($current_path === 'themes' && !empty($exclusions['themes'])) {
            foreach ($exclusions['themes'] as $theme) {
                $theme = trim($theme);
                if (!empty($theme)) {
                    $theme_path = WP_CONTENT_DIR . '/themes/' . $theme;
                    $theme_path = wp_normalize_path($theme_path);
                    $normalized_file = wp_normalize_path($file);
                    
                    if (strpos($normalized_file, $theme_path) === 0) {
                        // error_log('File excluded due to theme exclusion: ' . $theme);
                        return true;
                    }
                }
            }
        }

        if (pathinfo($file, PATHINFO_EXTENSION) === 'php' && !empty($exclusions['php_functions'])) {
            $content = @file_get_contents($file);
            if ($content !== false) {
                foreach ($exclusions['php_functions'] as $function) {
                    $function = trim($function);
                    if (!empty($function) && stripos($content, $function) !== false) {
                        // error_log('File excluded due to containing excluded PHP function: ' . $function);
                        return true;
                    }
                }
            }
        }

        return false;
    }

    private function is_regex_pattern($pattern) {
        return @preg_match('/^\/.*\/[a-zA-Z]*$/', $pattern);
    }
    
    private function process_security_checks_batch($session_id) {
        $scan_data = get_option($this->scan_session_key . '_' . $session_id);
        if (!$scan_data) {
            return ['type' => 'error', 'message' => 'Invalid session'];
        }
        
        $security_checks = array_keys($this->security_checks);
        $current_check = $security_checks[$scan_data['current_security_check_index']];
        
        // Process single security check
        $check_result = $this->process_security_check($current_check);
        $scan_data['results'][$current_check] = $check_result;
        $scan_data['completed_checks'][] = $current_check;
        $scan_data['current_security_check_index']++;
        
        update_option($this->scan_session_key . '_' . $session_id, $scan_data);
        
        $is_checks_complete = $scan_data['current_security_check_index'] >= count($security_checks);
        $progress = 50 + (($scan_data['current_security_check_index'] / count($security_checks)) * 50); // Security checks are remaining 50%
        
        return [
            'type' => 'progress',
            'phase' => 'security_checks',
            'progress' => $progress,
            'current_check' => $this->security_checks[$current_check]['title'],
            'completed_checks' => count($scan_data['completed_checks']),
            'total_checks' => count($this->security_checks),
            'is_complete' => $is_checks_complete,
            'message' => "Running {$this->security_checks[$current_check]['title']}"
        ];
    }
    
    private function process_security_check($check_type) {
        switch ($check_type) {
            case 'plugin_vulnerabilities':
                return $this->check_plugin_vulnerabilities(); // Will update with my notifier plugin code feature check 
            case 'wordpress_version':
                return $this->check_wordpress_version_security();
            default:
                return $this->perform_additional_security_checks();
        }
    }
    
    
    private function finalize_scan($session_id) {
        $scan_data = get_option($this->scan_session_key . '_' . $session_id);
        if (!$scan_data) {
            return ['type' => 'error', 'message' => 'Invalid session'];
        }
        
        // Initialize counters for different types of issues
        $issue_summary = [
            'critical' => 0,
            'high' => 0,
            'medium' => 0,
            'low' => 0,
            'info' => 0
        ];
        
        // Process core scan issues
        if (!empty($scan_data['issues'])) {
            foreach ($scan_data['issues'] as $issue) {
                // Core file issues are typically high severity
                $issue_summary['high'] += count($issue['issues']);
            }
        }
        
        // Process security check results
        if (!empty($scan_data['results'])) {
            foreach ($scan_data['results'] as $check_type => $check_results) {
                if (isset($check_results['issues'])) {
                    $this->categorize_security_issues($check_results['issues'], $issue_summary);
                }
            }
        }
        
        // Calculate total issues
        $total_issues = array_sum($issue_summary);
        
        // Determine overall security status
        $scan_status = $this->determine_security_status($issue_summary);
        
        // Save scan results
        $scan_results = [
            'core_scan' => ['issues' => $scan_data['issues']],
            'security_checks' => $scan_data['results'],
            'issue_summary' => $issue_summary
        ];
        
        $this->save_scan_history($scan_status, $scan_results);
        
        // Cleanup session data
        delete_option($this->scan_session_key . '_' . $session_id);
        
        return [
            'type' => 'complete',
            'total_issues' => $total_issues,
            'issue_summary' => $issue_summary,
            'status' => $scan_status,
            'results' => $scan_results
        ];
    }
    
    private function categorize_security_issues($issues, &$issue_summary) {
        foreach ($issues as $issue) {
            if (is_array($issue) && isset($issue['type'])) {
                switch ($issue['type']) {
                    case 'vulnerability':
                        $issue_summary['critical']++;
                        break;
                    case 'security_warning':
                        $issue_summary['high']++;
                        break;
                    case 'warning':
                        $issue_summary['medium']++;
                        break;
                    default:
                        $issue_summary['low']++;
                }
            } else {
                // Simple string issues are treated as medium severity
                $issue_summary['medium']++;
            }
        }
    }
    
    private function determine_security_status($issue_summary) {
        // Site is considered vulnerable only if there are critical or high severity issues
        if ($issue_summary['critical'] > 0) {
            return 'Critical';
        } elseif ($issue_summary['high'] > 0) {
            return 'Vulnerable';
        } elseif ($issue_summary['medium'] > 0) {
            return 'Warning';
        } elseif ($issue_summary['low'] > 0 || $issue_summary['info'] > 0) {
            return 'Notice';
        }
        
        return 'Secure';
    }

    private function send_progress_update($check_type, $title, $status, $progress) {
        // Ensure progress doesn't exceed 100
        $progress = min(100, max(0, $progress));
        
        wp_send_json_success([
            'type' => 'progress',
            'check' => $check_type,
            'title' => $title,
            'status' => $status,
            'progress' => $progress
        ]);
        flush();
    }


    private function deep_security_scan($path, $path_type, $exclusions) {
        $exclusions = $this->get_scan_exclusions();

        error_log('Exclusions 2: ' . print_r($exclusions, true));
         // Check if this path type is excluded
         if (in_array($path_type, $exclusions['core_files'] ?? []) ||
         in_array($path_type, $exclusions['plugins'] ?? []) ||
         in_array($path_type, $exclusions['themes'] ?? [])) {
            return ['path' => $path, 'issues' => [], 'files_checked' => 0];
         }

        // Existing deep scan logic, but modified to support exclusions
        $scan_results = [
            'path' => $path,
            'issues' => [],
            'files_checked' => 0
        ];
        $files = $this->get_all_files($path);
        foreach ($files as $file) {
            $scan_results['files_checked']++;
            // Check file against exclusion patterns
            if ($this->is_file_excluded($file, $exclusions)) {
                continue;
            }
            $file_issues = $this->check_file_security($file, $exclusions);
            if (!empty($file_issues)) {
                $scan_results['issues'][] = [
                    'file' => $file,
                    'issues' => $file_issues
                ];
            }
        }

        return $scan_results;
    }

    private function is_file_excluded($file, $exclusions) {
        // Check against file exclusion patterns
        $file_patterns = $exclusions['file_patterns'] ?? [];
        foreach ($file_patterns as $pattern) {
            if (fnmatch($pattern, $file)) {
                return true;
            }
        }
        return false;
    }

    private function get_all_files($directory) {
        $files = [];
        
        if (!is_dir($directory)) {
            return $files;
        }

        $iterator = new RecursiveIteratorIterator(
            new RecursiveDirectoryIterator($directory, RecursiveDirectoryIterator::SKIP_DOTS),
            RecursiveIteratorIterator::SELF_FIRST
        );

        foreach ($iterator as $file) {
            if (!$file->isDir()) {
                $files[] = $file->getPathname();
            }
        }

        return $files;
    }

    private function check_file_security($file, $exclusions) {
        $issues = [];
        
        // Modified file check to support function exclusions
        $content = @file_get_contents($file);
        $excluded_functions = $exclusions['php_functions'] ?? [];

        // Check for dangerous functions, but skip excluded ones
        foreach ($this->security_patterns['dangerous_functions'] as $function) {
            if (stripos($content, $function) !== false && !in_array($function, $excluded_functions)) {
                $issues[] = "Suspicious dangerous_functions pattern found: $function";
            }
        }

        return $issues;
    }

    private function perform_additional_security_checks() {
        $additional_checks = [
            'database_security' => $this->check_database_security(),
            'wordpress_config' => $this->check_wordpress_configuration()
        ];

        return $additional_checks;
    }

    private function check_database_security() {
        global $wpdb;
        $issues = [];
        // Check for default table prefix.
        if ($wpdb->prefix === 'wp_') {
            $issues[] = 'Using default database prefix increases vulnerability';
        }

        return $issues;
    }

    private function check_wordpress_configuration() {
        $issues = [];
        // Check debug mode
        if (defined('WP_DEBUG') && WP_DEBUG === true) {
            $issues[] = 'Debug mode is enabled - should be disabled in production';
        }

        return $issues;
    }

    private function log_scanning_file($file) {
        // Optional: We may add more detailed logging
        $this->scan_log[] = [
            'timestamp' => current_time('mysql'),
            'file' => $file
        ];
    }

    
    private function save_scan_history($status, $results) {
        $history = get_option($this->scan_history_option, []);
    
        // Ensure $history is an array
        if (!is_array($history)) {
            $history = []; // Reset to an empty array if it's not already an array
        }
    
        $new_scan = [
            'date' => current_time('mysql'),
            'status' => $status,
            'details' => $results,
        ];
    
        array_unshift($history, $new_scan);
        $history = array_slice($history, 0, 20);
    
        update_option($this->scan_history_option, $history);
    
        // Save detailed logs to a file
        $log_file = WP_CONTENT_DIR . '/security_scan_logs.txt';
        $log_content = 'Scan Date: ' . $new_scan['date'] . PHP_EOL;
        $log_content .= 'Scan Status: ' . $status . PHP_EOL;
        $log_content .= 'Issues: ' . print_r($results, true) . PHP_EOL;
        $log_content .= '-----------------------------' . PHP_EOL;
    
        file_put_contents($log_file, $log_content, FILE_APPEND);
    }

    

    public function get_scan_history() {
        $history = get_option($this->scan_history_option, []);
        wp_send_json_success($history);
    }


    // Exclude 
    public function update_scan_exclusions() {
        check_ajax_referer('wp_rest', 'nonce');
        
        $exclusions = [
            'paths' => isset($_POST['paths']) ? 
                array_map('sanitize_text_field', explode("\n", $_POST['paths'])) : [],
            'file_patterns' => isset($_POST['file_patterns']) ? 
                array_map('sanitize_text_field', explode("\n", $_POST['file_patterns'])) : [],
            'php_functions' => isset($_POST['php_functions']) ? 
                array_map('sanitize_text_field', explode("\n", $_POST['php_functions'])) : [],
            'core_files' => isset($_POST['core_files']) ? 
                array_map('sanitize_text_field', $_POST['core_files']) : [],
            'plugins' => isset($_POST['plugins']) ? 
                array_map('sanitize_text_field', $_POST['plugins']) : [],
            'themes' => isset($_POST['themes']) ? 
                array_map('sanitize_text_field', $_POST['themes']) : []
        ];

        update_option($this->exclusion_option, $exclusions);
        wp_send_json_success($exclusions);
    }

    // Method to retrieve current exclusions
    private function get_scan_exclusions() {
        return get_option($this->exclusion_option, [
            'paths' => [],
            'file_patterns' => [],
            'php_functions' => [],
            'core_files' => [],
            'plugins' => [],
            'themes' => []
        ]);
    }

    public function check_plugin_vulnerabilities() {
        $issues = [];
        $exclusions = $this->get_scan_exclusions();

        error_log('Exclusions 3: ' . print_r($exclusions, true));
        $plugins = get_plugins();
        $scan_results = [];

        // If 'plugins' is in core_files exclusions, skip the entire plugin scan.
        if (in_array('plugins', $exclusions['core_files'] ?? [])) {
            error_log('Skipping plugin scan: plugins are fully excluded.');
            return [
                'issues' => [],
                'files_checked' => 0
            ];
        }
    
        foreach ($plugins as $plugin_file => $plugin_data) {
            $plugin_slug = $this->get_plugin_slug($plugin_file);

            // Skip excluded plugins
            $excluded_slugs = array_map(function ($path) {
                return explode('/', $path)[0]; // Extracts the plugin folder name.
            }, $exclusions['plugins'] ?? []);

            // Skip excluded plugins
            if (in_array($plugin_slug, $excluded_slugs)) {
                continue;
            }
        
            // Fetch vulnerabilities using the correct slug
            $plugin_vulnerabilities = $this->fetch_vulnerable_plugins($plugin_slug, $plugin_data['Version']);
        
            if (!empty($plugin_vulnerabilities)) {
                $scan_results[] = [
                    'plugin' => $plugin_data['Name'],
                    'slug'   => $plugin_slug,
                    'version' => $plugin_data['Version'],
                    'vulnerabilities' => $plugin_vulnerabilities
                ];
            }

        }
    
        return [
            'issues' => $scan_results,
            'files_checked' => count($plugins)
        ];
    }


    // Simulated vulnerability check - replace with actual vulnerability database API
    private function fetch_vulnerable_plugins($name, $version) {
        $vulnerabilities = [];

        // error_log( 'Data Received:plugin_slug ' . print_r( $name, true ) );

        // If the plugin is premium, skip the security check
        if ($this->is_premium_plugin($name)) {
            return [];
        }

        $plugin_slug = sanitize_title($name);
        
        // 1. Check WordPress.org API for plugin information
        $api_url = 'https://api.wordpress.org/plugins/info/1.2/?action=plugin_information';
        $response = wp_remote_get(add_query_arg([
            'slug' => $plugin_slug,
            'fields' => [
                'versions' => true,
                'tested' => true,
                'requires' => true,
                'rating' => true,
                'last_updated' => true,
                'downloaded' => true,
                'active_installs' => true
            ]
        ], $api_url));

        if (is_wp_error($response)) {
            return [
                [
                    'type' => 'error',
                    'description' => 'Unable to check plugin security status',
                    'recommendation' => 'Please try again later or check plugin manually.'
                ]
            ];
        }
    
        $plugin_data = json_decode(wp_remote_retrieve_body($response));
        
        // Security checks based on free data
        if ($plugin_data) {
            // Check 1: Version outdated
            if (isset($plugin_data->version) && version_compare($version, $plugin_data->version, '<')) {
                $vulnerabilities[] = [
                    'type' => 'security_warning',
                    'description' => sprintf(
                        'Running outdated version %s. Latest version is %s',
                        esc_html($version),
                        esc_html($plugin_data->version)
                    ),
                    'recommendation' => 'Update to the latest version for security patches.'
                ];
            }
    
            // Check 2: Plugin abandoned
            $last_updated = isset($plugin_data->last_updated) ? strtotime($plugin_data->last_updated) : 0;
            if ($last_updated && (time() - $last_updated) > (365 * 24 * 60 * 60)) { // Over 1 year
                $vulnerabilities[] = [
                    'type' => 'warning',
                    'description' => 'Plugin has not been updated in over a year',
                    'recommendation' => 'Consider finding an actively maintained alternative.'
                ];
            }
    
            // Check 3: WordPress version compatibility
            global $wp_version;
            if (isset($plugin_data->tested) && version_compare($wp_version, $plugin_data->tested, '>')) {
                $vulnerabilities[] = [
                    'type' => 'warning',
                    'description' => sprintf(
                        'Plugin only tested up to WordPress %s (you\'re running %s)',
                        esc_html($plugin_data->tested),
                        esc_html($wp_version)
                    ),
                    'recommendation' => 'Check plugin compatibility with your WordPress version.'
                ];
            }
    
            // Check 4: Low installation count (might indicate unreliable plugin)
            if (isset($plugin_data->active_installs) && $plugin_data->active_installs < 100) {
                $vulnerabilities[] = [
                    'type' => 'warning',
                    'description' => 'Plugin has very few active installations',
                    'recommendation' => 'Verify plugin reliability and consider alternatives with larger user base.'
                ];
            }

            // Analyze ratings more thoroughly
            if (isset($plugin_data->ratings) && isset($plugin_data->num_ratings)) {
                $rating_analysis = $this->analyze_plugin_ratings($plugin_data->ratings, $plugin_data->num_ratings);
                if ($rating_analysis['flag']) {
                    $vulnerabilities[] = [
                        'type' => 'warning',
                        'description' => $rating_analysis['message'],
                        'recommendation' => 'Review plugin ratings and feedback carefully.'
                    ];
                }
            }
    
            // Check 5: Check against known vulnerable versions using simple database
            $known_vulnerable_versions = $this->get_known_vulnerable_versions($name);
            foreach ($known_vulnerable_versions as $vuln_version => $vuln_details) {
                if (version_compare($version, $vuln_version, '<=')) {
                    $vulnerabilities[] = [
                        'type' => 'vulnerability',
                        'description' => $vuln_details['description'],
                        'recommendation' => $vuln_details['fix']
                    ];
                }
            }
        } else {
            $vulnerabilities[] = [
                'type' => 'warning',
                'description' => 'Plugin not found in WordPress.org repository',
                'recommendation' => 'Verify the plugin source and ensure it\'s from a trusted developer.'
            ];
        }
    
        return $vulnerabilities;
    }

    private function get_plugin_slug($plugin_file) {
        $plugin_path = WP_PLUGIN_DIR . '/' . $plugin_file;
    
        // Ensure the file exists before attempting to read
        if (!file_exists($plugin_path)) {
            return false;
        }
    
        // Read plugin metadata
        $plugin_data = get_file_data($plugin_path, [
            'TextDomain' => 'Text Domain',
            'Name'       => 'Plugin Name',
            'PluginURI'  => 'Plugin URI'
        ]);
    
        // Log raw extracted data for debugging
        // error_log("Extracted Data: " . print_r($plugin_data, true));
    
        // 1. Use Text Domain first if available
        if (!empty($plugin_data['TextDomain'])) {
            return sanitize_title($plugin_data['TextDomain']);
        }
    
        // 2. Extract from Plugin URI if it's a WordPress.org plugin
        if (!empty($plugin_data['PluginURI'])) {
            if (preg_match('/wordpress\.org\/plugins\/([^\/]+)/', $plugin_data['PluginURI'], $matches)) {
                return sanitize_title($matches[1]);
            }
        }
    
        // 3. Extract from directory name
        if (strpos($plugin_file, '/') !== false) {
            $directory = dirname($plugin_file);
            return sanitize_title(basename($directory));
        }
    
        // 4. Fallback to filename without .php
        return sanitize_title(basename($plugin_file, '.php'));
    }
    
    


    
    private function get_known_vulnerable_versions($plugin_name) {
        $known_vulnerabilities = [
            'contact-form-7' => [
                '5.3.1' => [
                    'description' => 'XSS vulnerability in versions 5.3.1 and below',
                    'fix' => 'Update to version 5.3.2 or higher'
                ]
            ],
            'wordpress-seo' => [
                '17.8' => [
                    'description' => 'Authenticated SQLi vulnerability in versions 17.8 and below',
                    'fix' => 'Update to version 17.9 or higher'
                ]
            ],
            // Add more known vulnerabilities here.
        ];
    
        return $known_vulnerabilities[sanitize_title($plugin_name)] ?? [];
    }

    public function check_wordpress_version_security() {
        global $wp_version;
        $issues = [];
    
        // Check current WordPress version against recommended security version
        $latest_version = $this->get_latest_wordpress_version();
        
        if (version_compare($wp_version, $latest_version, '<')) {
            $issues[] = [
                'current_version' => $wp_version,
                'latest_version' => $latest_version,
                'message' => 'WordPress is outdated. Please update to the latest version.'
            ];
        }
    
        return [
            'issues' => $issues,
            'version_checked' => $wp_version
        ];
    }

    private function get_latest_wordpress_version() {
        // Use WordPress core API to check for updates
        $update_core = get_site_transient('update_core');
        
        // If transient doesn't exist or is expired, fetch fresh data
        if (!$update_core) {
            wp_version_check();
            $update_core = get_site_transient('update_core');
        }
        
        // Parse the update check response
        if ($update_core && property_exists($update_core, 'updates')) {
            foreach ($update_core->updates as $update) {
                // Look for the latest stable version
                if ($update->response === 'upgrade' && $update->channel === 'stable') {
                    return $update->version;
                }
            }
        }
        
        // Fallback: directly check WordPress API
        $api_url = 'https://api.wordpress.org/core/version-check/1.7/';
        $response = wp_remote_get($api_url);
        
        if (!is_wp_error($response)) {
            $api_response = json_decode(wp_remote_retrieve_body($response), true);
            if (isset($api_response['offers']) && is_array($api_response['offers'])) {
                foreach ($api_response['offers'] as $offer) {
                    if (isset($offer['response']) && $offer['response'] === 'upgrade' && 
                        isset($offer['current']) && !empty($offer['current'])) {
                        return $offer['current'];
                    }
                }
            }
        }
        
        // If all checks fail, return current WordPress version
        global $wp_version;
        return $wp_version;
    }

    private function is_premium_plugin($name) {
        $premium_patterns = [
            '/pro$/i',
            '/premium$/i',
            '/-pro-/i',
            '/-premium-/i'
        ];
        
        foreach ($premium_patterns as $pattern) {
            if (preg_match($pattern, $name)) {
                return true;
            }
        }
        
        return false;
    }
    
    private function analyze_plugin_ratings($ratings, $total_ratings) {
        if ($total_ratings < 10) {
            return [
                'flag' => true,
                'message' => 'Plugin has very few ratings to establish reliability'
            ];
        }
    
        // Convert stdClass to array and handle potential missing keys
        $ratings_array = (array)$ratings;
        $five_star = isset($ratings_array[5]) ? $ratings_array[5] : 0;
        $one_star = isset($ratings_array[1]) ? $ratings_array[1] : 0;
    
        // Calculate percentages
        $five_star_percent = ($five_star / $total_ratings) * 100;
        $one_star_percent = ($one_star / $total_ratings) * 100;
    
        if ($five_star_percent > 90 && $total_ratings < 50) {
            return [
                'flag' => true,
                'message' => 'Unusually high proportion of 5-star ratings with limited total ratings'
            ];
        }
    
        if ($one_star_percent > 30) {
            return [
                'flag' => true,
                'message' => 'High proportion of 1-star ratings indicates potential issues'
            ];
        }
    
        return ['flag' => false];
    }
    
    private function render_directory_checkboxes($type, $directories, $current_exclusions) {
        foreach ($directories as $dir) {
            $checked = in_array($dir, $current_exclusions) ? 'checked' : '';
            echo "<label>
                <input type='checkbox' 
                    name='{$type}[]' 
                    value='{$dir}' 
                    {$checked}
                /> {$dir}
            </label>";
        }
    }

    private function get_core_file_directories() {
        // Update this method to match the format used in the exclusions UI
        return [
            'core',
            '.htaccess',
            'wp-config.php',
            'wp-includes',
            'wp-admin',
            'mu-plugins',
            'uploads',
            'plugins',
            'themes'
        ];
    }

    private function get_installed_plugins() {
        $plugins = get_plugins();
        return array_keys($plugins);
    }

    private function get_installed_themes() {
        $themes = wp_get_themes();
        return array_keys($themes);
    }
}


new AdvancedWordPressSecurityScanner();