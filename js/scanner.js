jQuery(document).ready(function($) {
    let scanInProgress = false;
    let currentSession = null;
    // New
    function initializeScanUI() {
        const $progressBar = $('.progress-bar');
        const $progressText = $('.progress-text');
        const $resultsContainer = $('#current-scan-results');
        
        $progressBar.width('0%');
        $progressText.html('Initializing Scan...');
        $resultsContainer.empty();
        
        $resultsContainer.html(`
            <div class="scan-progress-details">
                <div class="current-check">
                    <div class="check-spinner"></div>
                    <span class="check-title">Preparing scan...</span>
                </div>
                <div class="scan-statistics">
                    <div class="stat-item files-processed">
                        <span class="stat-label">Files Processed:</span>
                        <span class="stat-value">0</span>
                    </div>
                    <div class="stat-item checks-completed">
                        <span class="stat-label">Checks Completed:</span>
                        <span class="stat-value">0</span>
                    </div>
                </div>
                <div class="checks-categories">
                    <div class="category core-checks">
                        <h4>Core Files Scan</h4>
                        <div class="category-checks"></div>
                    </div>
                    <div class="category security-checks">
                        <h4>Security Checks</h4>
                        <div class="category-checks"></div>
                    </div>
                </div>
            </div>
        `);
    } 

    function startBatchedScan() {
        // Initialize scan
        runScanPhase('initialize');
    }

    function runScanPhase(phase, session_id = null) {
        $.ajax({
            url: appLocalizer.ajax_url,
            type: 'POST',
            data: {
                action: 'run_security_scan',
                nonce: appLocalizer.nonce,
                scan_type: phase,
                session_id: session_id
            },
            success: function(response) {
                if (response.success) {
                    handleBatchResponse(response.data);
                } else {
                    handleScanError('Scan failed: ' + (response.data?.message || 'Unknown error'));
                }
            },
            error: function(xhr, status, error) {
                handleScanError('Scan failed: ' + error);
            }
        });
    }
    
    function handleBatchResponse(data) {
        switch (data.type) {
            case 'initialize':
                currentSession = data.session_id;
                updateProgress(0, 'Starting core files scan...');
                runScanPhase('core_files', currentSession);
                break;
                
            case 'progress':
                updateProgress(data.progress, data.message);
                updateScanStatistics(data);
                
                if (data.phase === 'core_files' && !data.is_complete) {
                    // Continue core files scan
                    runScanPhase('core_files', currentSession);
                } else if (data.phase === 'core_files' && data.is_complete) {
                    // Move to security checks
                    updateProgress(50, 'Starting security checks...');
                    runScanPhase('security_checks', currentSession);
                } else if (data.phase === 'security_checks' && !data.is_complete) {
                    // Continue security checks
                    runScanPhase('security_checks', currentSession);
                } else if (data.phase === 'security_checks' && data.is_complete) {
                    // Finalize scan
                    runScanPhase('finalize', currentSession);
                }
                break;
                
            case 'complete':
                completeScan(data);
                break;
        }
    }
    
    function updateProgress(progress, message) {
        const $progressBar = $('.progress-bar');
        const $progressText = $('.progress-text');
        const $currentCheck = $('.current-check');
        
        $progressBar.width(progress + '%');
        $progressText.html(`${Math.round(progress)}% Complete`);
        $currentCheck.html(`
            <div class="check-spinner"></div>
            <span class="check-title">${message}</span>
        `);
    }
    
    function updateScanStatistics(data) {
        if (data.phase === 'core_files') {
            $('.files-processed .stat-value').text(
                `${data.processed_files} / ${data.total_files}`
            );
        } else if (data.phase === 'security_checks') {
            $('.checks-completed .stat-value').text(
                `${data.completed_checks} / ${data.total_checks}`
            );
        }
        
        // Update category status
        const $categoryChecks = data.phase === 'core_files' 
            ? $('.core-checks .category-checks')
            : $('.security-checks .category-checks');
            
        if (data.current_path || data.current_check) {
            $categoryChecks.html(`
                <div class="check-item in-progress">
                    <span class="check-status-icon">⋯</span>
                    <span class="check-name">${data.current_path || data.current_check}</span>
                </div>
            `);
        }
    }

    // End
    // Scan start 
    $('#start-security-scan').on('click', function() {
        if (scanInProgress) return;
        
        scanInProgress = true;
        initializeScanUI();
        startBatchedScan();
    });

    // xclude 
    $('#exclusion-settings-form').on('submit', function(e) {
        e.preventDefault();

        var formData = {
            action: 'update_scan_exclusions',
            nonce: appLocalizer.nonce,
            paths: $('#exclude-paths').val(),
            file_patterns: $('#exclude-file-patterns').val(),
            php_functions: $('#exclude-functions').val(),
            core_files: [],
            plugins: [],
            themes: []
        };

        // Collect checkbox exclusions
        $('input[name="core_files[]"]:checked').each(function() {
            formData.core_files.push($(this).val());
        });

        $('input[name="plugins[]"]:checked').each(function() {
            formData.plugins.push($(this).val());
        });

        $('input[name="themes[]"]:checked').each(function() {
            formData.themes.push($(this).val());
        });

        $.ajax({
            url: appLocalizer.ajax_url,
            type: 'POST',
            data: formData,
            success: function(response) {
                if (response.success) {
                    alert('Exclusion settings saved successfully!');
                } else {
                    alert('Failed to save exclusion settings.');
                }
            },
            error: function() {
                alert('Error saving exclusion settings.');
            }
        });
    });
    
    function completeScan(data) {
        const $progressBar = $('.progress-bar');
        const $progressText = $('.progress-text');
        const $currentCheck = $('.current-check');
        const $resultsContainer = $('#current-scan-results');
        
        // Update UI to show completion
        $progressBar.width('100%');
        $progressText.html('Scan Complete');
        $currentCheck.html(`
            <span class="check-icon">✓</span>
            <span class="check-title">Scan Completed</span>
        `);
        
        // Display final results
        const resultsHtml = `
            <div class="scan-results">
                <h3>Scan Results</h3>
                <div class="results-summary">
                    <p>Status: <span class="status-${data.status.toLowerCase()}">${data.status}</span></p>
                    <p>Total Issues Found: ${data.total_issues}</p>
                </div>
                ${renderDetailedResults(data.results)}
            </div>
        `;
        
        $resultsContainer.append(resultsHtml);
        loadScanHistory();
    }
    
    function renderDetailedResults(results) {
        let html = '<div class="detailed-results">';
        
        for (const [category, result] of Object.entries(results)) {
            const issueCount = result.issues ? result.issues.length : 0;
            const statusClass = issueCount > 0 ? 'has-issues' : 'no-issues';
            
            html += `
                <div class="result-category ${statusClass}">
                    <h4>${formatCategoryName(category)}</h4>
                    <div class="category-summary">
                        <p>Issues Found: ${issueCount}</p>
                        ${result.files_checked ? `<p>Files Checked: ${result.files_checked}</p>` : ''}
                    </div>
                    ${renderIssuesList(result.issues)}
                </div>
            `;
        }
        
        html += '</div>';
        return html;
    }
    
    function renderIssuesList(issues) {
        if (!issues || issues.length === 0) {
            return '<p class="no-issues-found">No issues found</p>';
        }
        
        let html = '<ul class="issues-list">';
        for (const issue of issues) {
            if (typeof issue === 'string') {
                html += `<li>${escapeHtml(issue)}</li>`;
            } else {
                html += `
                    <li>
                        ${issue.file ? `<strong>File:</strong> ${escapeHtml(issue.file)}<br>` : ''}
                        ${issue.message ? `<strong>Issue:</strong> ${escapeHtml(issue.message)}` : ''}
                        ${issue.issues ? `<strong>Details:</strong> ${escapeHtml(issue.issues.join(', '))}` : ''}
                    </li>
                `;
            }
        }
        html += '</ul>';
        return html;
    }

    function loadScanHistory() {
        $.ajax({
            url: appLocalizer.ajax_url,
            type: 'POST',
            data: {
                action: 'get_scan_history',
                nonce: appLocalizer.nonce
            },
            success: function(response) {
                var $historyBody = $('#scan-history-body');
                console.log($historyBody)
                $historyBody.empty();

                $.each(response.data, function(index, scan) {

                    var totalIssues = countIssues(scan.issue_summary || scan.details.issue_summary);
                
                    var statusClass = scan.status.toLowerCase();
                    var row = '<tr data-scan-index="' + index + '">' +
                        '<td>' + scan.date + '</td>' +
                        '<td class="status-' + statusClass + '">' + scan.status + '</td>' +
                        '<td>' + totalIssues + '</td>' +
                        '<td><button data-scan-index="' + index + '" class="view-details-btn">View Details</button></td>' +
                        '</tr>';
                    $historyBody.append(row);
                });

                $('.view-details-btn').on('click', function() {
                    var scanIndex = $(this).closest('tr').data('scan-index');
                    fetchScanDetails(scanIndex);
                });
            }
        });
    }

    function fetchScanDetails(scanIndex) {
        $.ajax({
            url: appLocalizer.ajax_url,
            type: 'POST',
            data: {
                action: 'get_specific_scan_details',
                nonce: appLocalizer.nonce,
                scan_index: scanIndex
            },
            success: function(response) {
                if (response.success) {
                    renderScanDetails(response.data);
                } else {
                    alert('No scan details found');
                }
            },
            error: function() {
                alert('Failed to retrieve scan details');
            }
        });
    }

    /* function renderScanDetails(data) {
        const container = $('#current-scan-results');
        container.empty(); // Clear previous results
    
        // Create the main structure
        const detailsHTML = `
            <div class="scan-result">
                <h3>Scan Date: ${data.date}</h3>
                <p><strong>Status:</strong> ${data.status}</p>
                <div class="scan-details">
                    <h4>Details:</h4>
                    ${renderCoreDetails(data.details.core)}
                </div>
            </div>
        `;
    
        container.html(detailsHTML);
    } */

    // New
    function renderScanDetails(data) {
        const container = $('#current-scan-results');
        container.empty();
        
        const detailsHTML = `
            <div class="scan-result">
                <h3>Scan Date: ${data.date}</h3>
                <p class="status-${data.status.toLowerCase()}"><strong>Status:</strong> ${data.status}</p>
                <div class="scan-details">
                    ${renderSecuritySection(data.details)}
                </div>
            </div>
        `;
    
        container.html(detailsHTML);
    }
    
    function renderSecuritySection(details) {
        if (!details) return '<p>No scan details available.</p>';
        
        let sectionsHTML = '';
        
        // Core Scan Section
        if (details.core_scan) {
            sectionsHTML += `
                <div class="section core-scan">
                    <h4>Core Files Scan</h4>
                    ${details.core_scan.issues && details.core_scan.issues.length > 0 
                        ? renderIssuesList(details.core_scan.issues)
                        : '<p class="no-issues">No core file issues found.</p>'
                    }
                </div>
            `;
        }
        
        // Security Checks Section
        if (details.security_checks) {
            sectionsHTML += '<div class="section security-checks"><h4>Security Checks</h4>';
            
            // WordPress Version Check
            if (details.security_checks.wordpress_version) {
                const wpVersion = details.security_checks.wordpress_version;
                sectionsHTML += `
                    <div class="subsection wordpress-version">
                        <h5>WordPress Version</h5>
                        <p>Current Version: ${wpVersion.version_checked}</p>
                        ${wpVersion.issues && wpVersion.issues.length > 0 
                            ? renderIssuesList(wpVersion.issues)
                            : '<p class="no-issues">WordPress version is up to date.</p>'
                        }
                    </div>
                `;
            }
            
            // Plugin Vulnerabilities
            if (details.security_checks.plugin_vulnerabilities) {
                const pluginCheck = details.security_checks.plugin_vulnerabilities;
                sectionsHTML += `
                    <div class="subsection plugin-vulnerabilities">
                        <h5>Plugin Vulnerabilities</h5>
                        <p>Files Checked: ${pluginCheck.files_checked}</p>
                        ${renderPluginIssues(pluginCheck.issues)}
                    </div>
                `;
            }
            
            sectionsHTML += '</div>';
        }
        
        return sectionsHTML;
    }
    
    function renderPluginIssues(issues) {
        if (!issues || issues.length === 0) {
            return '<p class="no-issues">No plugin vulnerabilities found.</p>';
        }
        
        let html = '<div class="plugin-issues">';
        
        issues.forEach(plugin => {
            html += `
                <div class="plugin-issue">
                    <h6>${escapeHtml(plugin.plugin)} (v${escapeHtml(plugin.version)})</h6>
                    <ul class="vulnerability-list">
                        ${plugin.vulnerabilities.map(vuln => `
                            <li class="vulnerability-item ${vuln.type}">
                                <span class="vuln-type">${formatVulnType(vuln.type)}</span>
                                <p class="vuln-description">${escapeHtml(vuln.description)}</p>
                                ${vuln.recommendation ? `
                                    <p class="vuln-recommendation"><strong>Recommendation:</strong> ${escapeHtml(vuln.recommendation)}</p>
                                ` : ''}
                            </li>
                        `).join('')}
                    </ul>
                </div>
            `;
        });
        
        html += '</div>';
        return html;
    }
    
    function formatVulnType(type) {
        return type
            .split('_')
            .map(word => word.charAt(0).toUpperCase() + word.slice(1))
            .join(' ');
    }
    
    function renderIssuesList(issues) {
        if (!issues || issues.length === 0) {
            return '<p class="no-issues">No issues found.</p>';
        }
        
        return `
            <ul class="issues-list">
                ${issues.map(issue => `
                    <li class="issue-item">
                        ${issue.file ? `<strong>File:</strong> ${escapeHtml(issue.file)}<br>` : ''}
                        ${Array.isArray(issue.issues) 
                            ? issue.issues.map(subIssue => `<p>${escapeHtml(subIssue)}</p>`).join('')
                            : `<p>${escapeHtml(issue)}</p>`
                        }
                    </li>
                `).join('')}
            </ul>
        `;
    } 
    // End 
    
    function renderCoreDetails(core) {
        if (!core) return '<p>No core details available.</p>';
    
        // Render the issues in a readable format
        const issuesHTML = core.issues 
            ? core.issues.map(issue => `
                <li>
                    <strong>File:</strong> ${issue.file || 'N/A'}<br>
                    <strong>Issue:</strong> ${issue.issues ? issue.issues.join('<br>') : 'N/A'}
                </li>
            `).join('')
            : '<p>No issues found.</p>';
    
        return `
            <div class="core-details">
                <h5>Core Details:</h5>
                <ul>
                    <li><strong>Total files checked:</strong> ${core.files_checked || 'N/A'}</li>
                    <li><strong>Path:</strong> ${core.path || 'N/A'}</li>
                    <li><strong>Issues:</strong><ul>${issuesHTML}</ul></li>
                </ul>
            </div>
        `;
    }
    
    function countIssues(issueSummary) {
        var totalIssues = 0;
    
        // Ensure issueSummary is a valid object
        if (typeof issueSummary === "string") {
            try {
                issueSummary = JSON.parse(issueSummary); // Decode if it's a JSON string
            } catch (e) {
                console.error("Error parsing issueSummary:", e);
                return 0;
            }
        }
    
        if (typeof issueSummary === "object" && issueSummary !== null) {
            $.each(issueSummary, function(category, count) {
                totalIssues += parseInt(count, 10) || 0; // Ensure count is a number
            });
        } else {
            console.error("Invalid issueSummary format:", issueSummary);
        }
    
        return totalIssues;
    }

        

    function formatCategoryName(category) {
        return category
            .split('_')
            .map(word => word.charAt(0).toUpperCase() + word.slice(1))
            .join(' ');
    }
    
    function escapeHtml(unsafe) {
        return unsafe
            .replace(/&/g, "&amp;")
            .replace(/</g, "&lt;")
            .replace(/>/g, "&gt;")
            .replace(/"/g, "&quot;")
            .replace(/'/g, "&#039;");
    }
    
    function handleScanError(message) {
        scanInProgress = false;
        const $progressBar = $('.progress-bar');
        const $progressText = $('.progress-text');
        const $resultsContainer = $('#current-scan-results');
        
        $progressBar.width('100%').css('background-color', '#ef4444');
        $progressText.html('Scan Failed');
        $resultsContainer.append(`
            <div class="scan-error">
                <h3>Error</h3>
                <p>${escapeHtml(message)}</p>
            </div>
        `);
    }

    loadScanHistory();
});