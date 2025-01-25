<?php
/*
Plugin Name: Advanced WordPress Security Scanner
Plugin URI: https://example.com/advanced-security-scanner
Description: Comprehensive WordPress security scanning with detailed dashboard and history tracking
Version: 1.0
Author: sabbirsam
*/

class AdvancedWordPressSecurityScanner {
    private $scan_history_option = 'wps_security_scan_history_1';
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
        
        wp_localize_script('security-scanner-script', 'securityScannerAjax', [
            'ajax_url' => admin_url('admin-ajax.php'),
            'nonce' => wp_create_nonce('security_scan_nonce')
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
    private $security_patterns = [
        'dangerous_functions' => [
            'base64_decode', 'eval(', 'system(', 'exec(', 
            'shell_exec(', 'passthru(', 'proc_open(', 'popen('
        ],
        'obfuscation_indicators' => [
            'gzinflate', 'str_rot13', 'chr(', 'base64_encode'
        ],
        'malware_signatures' => [
            'wp_redirect', 'file_get_contents', 'curl_exec', 
            'include_once', 'require_once'
        ]
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
                            <h4>Core Files</h4>
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
            
            <div class="scan-results-container">
                <h2>Scan Results</h2>
                <div id="current-scan-results"></div>
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
        check_ajax_referer('security_scan_nonce', 'nonce');
    
        $scan_index = isset($_POST['scan_index']) ? intval($_POST['scan_index']) : -1;
        $history = get_option($this->scan_history_option, []);

        if ($scan_index >= 0 && $scan_index < count($history)) {
            wp_send_json_success($history[$scan_index]);
        } else {
            wp_send_json_error('Scan details not found');
        }
    }
    

    public function run_security_scan() {
        $scan_results = [];
        $total_issues = 0;
        $exclusions = $this->get_scan_exclusions();

        // Additional security scans
        $additional_checks = [
            'plugin_vulnerabilities' => $this->check_plugin_vulnerabilities(),
            'wordpress_version' => $this->check_wordpress_version_security(),
            'login_security' => $this->check_login_security(),
            'form_vulnerabilities' => $this->check_form_vulnerabilities()
        ];

        // Comprehensive scanning of all defined paths with exclusion support
        foreach ($this->scan_paths as $path_type => $path) {
            if (in_array($path_type, $exclusions['paths'] ?? [])) {
                continue; // Skip excluded paths
            }

            $path_scan_result = $this->deep_security_scan($path, $path_type, $exclusions);
            $scan_results[$path_type] = $path_scan_result;
            $total_issues += count($path_scan_result['issues']);
        }

        // Merge additional checks with scan results
        $scan_results = array_merge($scan_results, $additional_checks);
        foreach ($additional_checks as $check_name => $check_results) {
            $total_issues += count($check_results);
        }

        $scan_status = $total_issues > 0 ? 'Vulnerable' : 'Secure';
        $this->save_scan_history($scan_status, $scan_results);

        wp_send_json_success([
            'results' => $scan_results,
            'total_issues' => $total_issues,
            'status' => $scan_status,
            'scan_log' => $this->scan_log
        ]);
    }

    private function deep_security_scan($path, $path_type, $exclusions) {

        $exclusions = $this->get_scan_exclusions();

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
            'user_roles' => $this->check_user_roles(),
            'wordpress_config' => $this->check_wordpress_configuration()
        ];

        return $additional_checks;
    }

    private function check_database_security() {
        global $wpdb;
        $issues = [];

        // Check for default table prefix
        if ($wpdb->prefix === 'wp_') {
            $issues[] = 'Using default database prefix increases vulnerability';
        }

        return $issues;
    }

    private function check_user_roles() {
        $issues = [];
        $users = get_users();

        foreach ($users as $user) {
            if ($user->has_cap('administrator') && $user->user_login === 'admin') {
                $issues[] = 'Default admin account detected - potential security risk';
            }
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
        
        $new_scan = [
            'date' => current_time('mysql'),
            'status' => $status,
            'details' => $results,
            // 'log' => $this->scan_log
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
    // Method to update scan exclusions
    // Unified method to update all exclusions
    public function update_scan_exclusions() {
        check_ajax_referer('security_scan_nonce', 'nonce');
        
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

    private function check_plugin_vulnerabilities() {
        $issues = [];
        $exclusions = $this->get_scan_exclusions();

        // Get all installed plugins
        $plugins = get_plugins();
        
        foreach ($plugins as $plugin_path => $plugin_data) {
            // Check if this plugin is in exclusion list
            if (in_array($plugin_path, $exclusions['plugin_versions'] ?? [])) {
                continue;
            }

            // Check plugin version against known vulnerabilities
            $vulnerable_plugins = $this->fetch_vulnerable_plugins($plugin_data['Name'], $plugin_data['Version']);
            if (!empty($vulnerable_plugins)) {
                $issues[] = [
                    'plugin' => $plugin_data['Name'],
                    'version' => $plugin_data['Version'],
                    'vulnerabilities' => $vulnerable_plugins
                ];
            }
        }

        return $issues;
    }


    // Simulated vulnerability check - replace with actual vulnerability database API
    private function fetch_vulnerable_plugins($name, $version) {
        // Placeholder: Would typically use an external vulnerability database
        $known_vulnerabilities = [
            // Example: 'Contact Form 7' => ['versions' => ['<5.5.6'], 'description' => 'XSS vulnerability']
        ];

        // Implement actual vulnerability checking logic here
        return [];
    }

    private function check_wordpress_version_security() {
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

        return $issues;
    }

    private function get_latest_wordpress_version() {
        // Placeholder: Would typically fetch from WordPress.org API
        // Implement actual version checking logic
        return '6.3'; // Example latest version
    }

    private function check_login_security() {
        $issues = [];

        // Check for brute force protection
        $login_attempts = get_option('login_attempts', []);
        $current_time = time();

        foreach ($login_attempts as $ip => $attempts) {
            if (count($attempts) > 5 && ($current_time - $attempts[0]) < 3600) {
                $issues[] = [
                    'ip' => $ip,
                    'attempts' => count($attempts),
                    'message' => 'Multiple failed login attempts detected'
                ];
            }
        }

        return $issues;
    }

    private function check_form_vulnerabilities() {
        $issues = [];
        
        // Check all forms for potential CSRF vulnerability
        $forms = apply_filters('security_form_scan', []);
        
        foreach ($forms as $form) {
            if (!$form->has_nonce_protection()) {
                $issues[] = [
                    'form_id' => $form->id,
                    'message' => 'Form lacks CSRF protection'
                ];
            }
        }

        return $issues;
    }


    //===
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
        return [
            'wp-admin',
            'wp-includes',
            'wp-content',
            'index.php',
            'wp-config.php'
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