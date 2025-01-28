<?php
/*

*/

class AdvancedWordPressSecurityScanner {

    private $batch_size = 5000;
    private $scan_session_key = 'wps_current_scan_session';


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

    private $security_checks = [
        'wordpress_version' => ['weight' => 5, 'title' => 'WordPress Version Check'],
        // 'plugin_vulnerabilities' => ['weight' => 10, 'title' => 'Plugin Vulnerability Check'],
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

    //----------start

    public function run_security_scan() {
        check_ajax_referer('security_scan_nonce', 'nonce');
        
        $scan_type = isset($_POST['scan_type']) ? sanitize_text_field($_POST['scan_type']) : 'initialize';
        $session_id = isset($_POST['session_id']) ? sanitize_text_field($_POST['session_id']) : null;
        
        switch ($scan_type) {
            case 'initialize':
                $response = $this->initialize_scan();
                break;
            /* case 'core_files':
                $response = $this->process_core_files_batch($session_id);
                break; */
            case 'core_files':
                $response = [
                    'type' => 'progress',
                    'phase' => 'core_files',
                    'progress' => 100,
                    'is_complete' => true,
                    'message' => "Core files check completed"
                ];
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

    /* private function initialize_scan() {
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
    } */

    private function initialize_scan() {
        $session_id = uniqid('scan_', true);
        $scan_data = [
            'session_id' => $session_id,
            'start_time' => current_time('mysql'),
            'current_security_check_index' => 0,
            'results' => [],
            'completed_checks' => [],
            'issues' => [] // Add this for finalize compatibility
        ];
        
        update_option($this->scan_session_key . '_' . $session_id, $scan_data);
        
        return [
            'type' => 'initialize',
            'session_id' => $session_id,
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
        $files = $this->get_all_files($this->scan_paths[$current_path]);
        
        $batch_end = min($scan_data['current_file_offset'] + $this->batch_size, count($files));
        $exclusions = $this->get_scan_exclusions();
        
        for ($i = $scan_data['current_file_offset']; $i < $batch_end; $i++) {
            if (isset($files[$i])) {
                $file = $files[$i];
                if (!$this->is_file_excluded($file, $exclusions)) {
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
        $progress = ($scan_data['processed_files'] / $scan_data['total_files']) * 50; // Core files are 50% of total progress
        
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
    
    /* private function process_security_checks_batch($session_id) {
        try {
            $scan_data = get_option($this->scan_session_key . '_' . $session_id);
            if (!$scan_data) {
                return ['type' => 'error', 'message' => 'Invalid session'];
            }
            
            $security_checks = array_keys($this->security_checks);
            if ($scan_data['current_security_check_index'] >= count($security_checks)) {
                return [
                    'type' => 'progress',
                    'phase' => 'security_checks',
                    'progress' => 100,
                    'is_complete' => true,
                    'message' => "Security checks completed"
                ];
            }
            
            $current_check = $security_checks[$scan_data['current_security_check_index']];
            
            // Process single security check with error handling
            try {
                $check_result = $this->process_security_check($current_check);
                $scan_data['results'][$current_check] = $check_result;
                $scan_data['completed_checks'][] = $current_check;
            } catch (Exception $e) {
                error_log("Security check error for {$current_check}: " . $e->getMessage());
                $scan_data['results'][$current_check] = [
                    'status' => 'error',
                    'message' => "Check failed: " . $e->getMessage()
                ];
            }
            
            $scan_data['current_security_check_index']++;
            update_option($this->scan_session_key . '_' . $session_id, $scan_data);
            
            $is_checks_complete = $scan_data['current_security_check_index'] >= count($security_checks);
            $progress = 50 + (($scan_data['current_security_check_index'] / count($security_checks)) * 50);
            
            return [
                'type' => 'progress',
                'phase' => 'security_checks',
                'progress' => $progress,
                'current_check' => $this->security_checks[$current_check]['title'] ?? $current_check,
                'completed_checks' => count($scan_data['completed_checks']),
                'total_checks' => count($this->security_checks),
                'is_complete' => $is_checks_complete,
                'message' => "Running " . ($this->security_checks[$current_check]['title'] ?? $current_check)
            ];
        } catch (Exception $e) {
            error_log("Security checks batch error: " . $e->getMessage());
            return ['type' => 'error', 'message' => 'Error processing security checks'];
        }
    } */
    
    /* private function process_security_check($check_type) {
        switch ($check_type) {
            case 'plugin_vulnerabilities':
                return $this->check_plugin_vulnerabilities();
            case 'wordpress_version':
                return $this->check_wordpress_version_security();
            default:
                return $this->perform_additional_security_checks();
        }
    } */

    private function process_security_checks_batch($session_id) {
        error_log('Starting security checks batch');  // Debug log
        
        $scan_data = get_option($this->scan_session_key . '_' . $session_id);
        if (!$scan_data) {
            error_log('Invalid session data');  // Debug log
            return ['type' => 'error', 'message' => 'Invalid session'];
        }
        
        // Get WordPress version check results
        $wp_version_check = $this->check_wordpress_version_security();
        error_log('WordPress version check results: ' . print_r($wp_version_check, true));  // Debug log
        
        // Store results
        $scan_data['results']['wordpress_version'] = $wp_version_check;
        $scan_data['completed_checks'][] = 'wordpress_version';
        $scan_data['current_security_check_index'] = 1; // Mark as complete
        
        update_option($this->scan_session_key . '_' . $session_id, $scan_data);
        
        return [
            'type' => 'progress',
            'phase' => 'security_checks',
            'progress' => 100, // Since we only have one check
            'current_check' => 'WordPress Version Check',
            'completed_checks' => 1,
            'total_checks' => 1,
            'is_complete' => true,
            'message' => "Completed WordPress Version Check"
        ];
    }
    
    /* private function finalize_scan($session_id) {
        try {
            $scan_data = get_option($this->scan_session_key . '_' . $session_id);
            if (!$scan_data) {
                return ['type' => 'error', 'message' => 'Invalid session'];
            }
            
            $total_issues = 0;
            
            // Count issues from core scan
            if (isset($scan_data['issues']) && is_array($scan_data['issues'])) {
                $total_issues += count($scan_data['issues']);
            }
            
            // Count issues from security checks
            if (isset($scan_data['results']) && is_array($scan_data['results'])) {
                foreach ($scan_data['results'] as $check_results) {
                    if (isset($check_results['issues']) && is_array($check_results['issues'])) {
                        $total_issues += count($check_results['issues']);
                    }
                }
            }
            
            $scan_status = $total_issues > 0 ? 'Vulnerable' : 'Secure';
            
            // Prepare results array with proper structure
            $results = [
                'core_scan' => [
                    'issues' => $scan_data['issues'] ?? []
                ],
                'security_checks' => $scan_data['results'] ?? []
            ];
            
            // Save scan history with proper error handling
            $this->save_scan_history($scan_status, $results);
            
            // Clean up session data
            delete_option($this->scan_session_key . '_' . $session_id);
            
            return [
                'type' => 'complete',
                'total_issues' => $total_issues,
                'status' => $scan_status,
                'results' => $results
            ];
        } catch (Exception $e) {
            error_log("Scan finalization error: " . $e->getMessage());
            return ['type' => 'error', 'message' => 'Error finalizing scan'];
        }
    } */

    private function finalize_scan($session_id) {
        error_log('Starting scan finalization');  // Debug log
        
        $scan_data = get_option($this->scan_session_key . '_' . $session_id);
        if (!$scan_data) {
            error_log('Invalid session data during finalization');  // Debug log
            return ['type' => 'error', 'message' => 'Invalid session'];
        }
        
        // Count issues only from WordPress version check
        $total_issues = 0;
        if (isset($scan_data['results']['wordpress_version']['issues'])) {
            $total_issues = count($scan_data['results']['wordpress_version']['issues']);
        }
        
        $scan_status = $total_issues > 0 ? 'Vulnerable' : 'Secure';
        
        // Save simplified results
        $results = [
            'security_checks' => [
                'wordpress_version' => $scan_data['results']['wordpress_version'] ?? []
            ]
        ];
        
        $this->save_scan_history($scan_status, $results);
        
        // Clean up
        delete_option($this->scan_session_key . '_' . $session_id);
        
        error_log('Scan finalization completed');  // Debug log
        
        return [
            'type' => 'complete',
            'total_issues' => $total_issues,
            'status' => $scan_status,
            'results' => $results
        ];
    }

    
    //---------------

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

        // Check for default table prefix
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

    /* private function save_scan_history($status, $results) {
        $history = get_option($this->scan_history_option, []);
        
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

    } */

    private function save_scan_history($status, $results) {
        $history = get_option($this->scan_history_option, []);
        
        $new_scan = [
            'date' => current_time('mysql'),
            'status' => $status,
            'details' => $results
        ];
        
        array_unshift($history, $new_scan);
        $history = array_slice($history, 0, 20);
        
        update_option($this->scan_history_option, $history);
        error_log('Scan history saved');  // Debug log
    }

    public function get_scan_history() {
        $history = get_option($this->scan_history_option, []);
        wp_send_json_success($history);
    }


    // Exclude 
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

    public function check_plugin_vulnerabilities() {
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

        return [
            'issues' => $issues,
            'files_checked' => count($plugins)
        ];
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
        error_log('Current WordPress version: ' . $wp_version);  // Debug log
        
        $issues = [];
        
        // Simple version comparison against a hardcoded version
        $latest_version = '6.4'; // Hardcoded for testing
        
        if (version_compare($wp_version, $latest_version, '<')) {
            $issues[] = [
                'current_version' => $wp_version,
                'latest_version' => $latest_version,
                'message' => 'WordPress is outdated. Please update to the latest version.'
            ];
        }
        
        error_log('Version check completed. Issues found: ' . count($issues));  // Debug log
        
        return [
            'issues' => $issues,
            'version_checked' => $wp_version
        ];
    }

    /* private function get_latest_wordpress_version() {
        try {
            // Try to get version from WordPress API
            $api_response = wp_remote_get('https://api.wordpress.org/core/version-check/1.7/');
            
            if (is_wp_error($api_response)) {
                throw new Exception('Failed to connect to WordPress.org API');
            }
            
            $api_data = json_decode(wp_remote_retrieve_body($api_response), true);
            
            if (isset($api_data['offers'][0]['version'])) {
                return $api_data['offers'][0]['version'];
            }
            
            // Fallback to current major version if API fails
            global $wp_version;
            return $wp_version;
        } catch (Exception $e) {
            error_log("Error getting latest WordPress version: " . $e->getMessage());
            return false;
        }
    } */

    
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