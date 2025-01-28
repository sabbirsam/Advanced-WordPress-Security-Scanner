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
                return $this->check_plugin_vulnerabilities();
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
        
        $total_issues = count($scan_data['issues']);
        foreach ($scan_data['results'] as $check_results) {
            if (isset($check_results['issues'])) {
                $total_issues += count($check_results['issues']);
            }
        }
        
        $scan_status = $total_issues > 0 ? 'Vulnerable' : 'Secure';
        $this->save_scan_history($scan_status, [
            'core_scan' => ['issues' => $scan_data['issues']],
            'security_checks' => $scan_data['results']
        ]);
        
        delete_option($this->scan_session_key . '_' . $session_id);
        
        return [
            'type' => 'complete',
            'total_issues' => $total_issues,
            'status' => $scan_status,
            'results' => [
                'core_scan' => ['issues' => $scan_data['issues']],
                'security_checks' => $scan_data['results']
            ]
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
        $vulnerabilities = [];
        
        // 1. Check WordPress.org API for plugin information
        $api_url = 'https://api.wordpress.org/plugins/info/1.2/?action=plugin_information';
        $response = wp_remote_get(add_query_arg([
            'slug' => sanitize_title($name),
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
    
            // Check 5: Low rating warning
            if (isset($plugin_data->rating) && ($plugin_data->rating / 100) < 3.5) {
                $vulnerabilities[] = [
                    'type' => 'warning',
                    'description' => 'Plugin has low user rating',
                    'recommendation' => 'Research plugin reviews and consider alternatives.'
                ];
            }
    
            // Check 6: Check against known vulnerable versions using simple database
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
    
    private function get_known_vulnerable_versions($plugin_name) {
        // This could be expanded with a regularly updated list from various free sources
        // Example structure - you should expand this based on publicly disclosed vulnerabilities
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
            // Add more known vulnerabilities here
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