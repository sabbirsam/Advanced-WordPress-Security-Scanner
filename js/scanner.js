jQuery(document).ready(function($) {
    $('#start-security-scan').on('click', function() {
        var $progressBar = $('.progress-bar');
        var $progressText = $('.progress-text');
        var $currentScanPath = $('#current-scan-path');
        var $resultsContainer = $('#current-scan-results');

        $progressBar.width('0%');
        $progressText.text('Initializing Scan...');
        $currentScanPath.empty();
        $resultsContainer.empty();

        $.ajax({
            url: securityScannerAjax.ajax_url,
            type: 'POST',
            data: {
                action: 'run_security_scan',
                nonce: securityScannerAjax.nonce
            },
            success: function(response) {
                $progressBar.width('100%');
                $progressText.text('Scan Complete');
                $currentScanPath.text('Scan Finished');

                // Detailed results display
                var htmlResults = '<div class="scan-details">';
                htmlResults += '<h3>Comprehensive Scan Results</h3>';
                
                $.each(response.data.results, function(category, result) {
                    var status = (result.issues && result.issues.length > 0) ? 'error' : 'success';
                    htmlResults += '<div class="scan-category ' + status + '">' +
                        '<h4>' + category.toUpperCase() + '</h4>' +
                        '<p>Files Checked: ' + (result.files_checked || 'N/A') + '</p>' +
                        '<p>' + (result.issues ? 'Issues Found: ' + result.issues.length : 'No Issues Detected') + '</p>' +
                        '</div>';
                });
                htmlResults += '</div>';

                $resultsContainer.html(htmlResults);

                // Refresh and update scan history
                loadScanHistory();
            },
            error: function() {
                $progressText.text('Scan Failed');
                $progressBar.width('100%');
                $resultsContainer.html('<div class="error">Security scan encountered an error</div>');
            }
        });
    });

    function loadScanHistory() {
        $.ajax({
            url: securityScannerAjax.ajax_url,
            type: 'POST',
            data: {
                action: 'get_scan_history',
                nonce: securityScannerAjax.nonce
            },
            success: function(response) {
                var $historyBody = $('#scan-history-body');
                console.log($historyBody)
                $historyBody.empty();

                $.each(response.data, function(index, scan) {
                    var totalIssues = countIssues(scan.details);
                    var row = '<tr data-scan-index="' + index + '">' +
                        '<td>' + scan.date + '</td>' +
                        '<td class="status-' + (scan.status === 'Secure' ? 'success' : 'error') + '">' + scan.status + '</td>' +
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
            url: securityScannerAjax.ajax_url,
            type: 'POST',
            data: {
                action: 'get_specific_scan_details',
                nonce: securityScannerAjax.nonce,
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

    function renderScanDetails(data) {
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
    }
    
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
    

    function countIssues(details) {
        var totalIssues = 0;
        $.each(details, function(category, result) {
            if (result.issues) {
                totalIssues += result.issues.length;
            }
        });
        return totalIssues;
    }

    loadScanHistory();
});

jQuery(document).ready(function($) {
    $('#exclusion-settings-form').on('submit', function(e) {
        e.preventDefault();

        var formData = {
            action: 'update_scan_exclusions',
            nonce: securityScannerAjax.nonce,
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
            url: securityScannerAjax.ajax_url,
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
});
