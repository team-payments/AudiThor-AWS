/**
 * 05_waf.js
 * Contiene toda la lógica para construir y renderizar la vista de WAF & Shield.
 */

// Importamos las funciones de utilidad que vamos a necesitar desde el fichero utils.js
import { handleTabClick, renderSecurityHubFindings, createStatusBadge } from '../utils.js';

// --- SERVICE DESCRIPTIONS ---
const serviceDescriptions = {
    webacl: {
        title: "Web Application Firewall (WAF)",
        description: "AWS WAF is a web application firewall that helps protect web applications and APIs from common web exploits and vulnerabilities by filtering, monitoring, and blocking malicious traffic based on configurable rules.",
        useCases: "Protection against SQL injection, cross-site scripting (XSS), DDoS mitigation, bot protection, rate limiting, geo-blocking, and custom security rules for web applications.",
        auditConsiderations: "Review rule configurations for completeness, verify logging is enabled for compliance and incident response, ensure rate limiting rules are properly configured, validate that all critical web applications are protected, and check that rules are regularly updated to address new threats."
    },
    ipsets: {
        title: "IP Sets Management",
        description: "IP Sets allow you to create reusable collections of IP addresses and IP address ranges that can be referenced in WAF rules, providing efficient management of allow/block lists and reducing rule complexity.",
        useCases: "IP-based access control, geographic restrictions, known malicious IP blocking, trusted partner IP allowlisting, and dynamic threat intelligence integration.",
        auditConsiderations: "Verify IP sets are regularly updated with current threat intelligence, ensure legitimate business IPs are not accidentally blocked, review geographic restrictions align with business requirements, and validate that IP ranges are properly maintained and documented."
    },
    logging: {
        title: "WAF Logging & Monitoring",
        description: "WAF logging captures detailed information about web requests that are allowed or blocked by your rules, providing visibility into attack patterns and helping with security monitoring and compliance requirements.",
        useCases: "Security incident investigation, compliance reporting, attack pattern analysis, rule effectiveness measurement, and integration with SIEM systems for comprehensive security monitoring.",
        auditConsiderations: "Ensure comprehensive logging is enabled for all WAF rules, verify logs are properly retained per compliance requirements, validate that sensitive data is not logged inappropriately, and confirm logs are monitored for security incidents and rule tuning opportunities."
    }
};

// La función principal que construye toda la vista. La exportamos para que otros ficheros puedan usarla.
export function buildWafView() {
    const container = document.getElementById('waf-view');
    if (!window.wafApiData || !window.securityHubApiData) {
        console.warn("WAF or Security Hub data not available for rendering.");
        return;
    }
    
    const { acls, ip_sets } = window.wafApiData.results;
    const wafFindings = window.securityHubApiData.results.findings.wafFindings;

    container.innerHTML = `
        <header class="flex justify-between items-center mb-6">
            <div>
                <h2 class="text-2xl font-bold text-[#204071]">WAF & Shield</h2>
                <p class="text-sm text-gray-500">${window.wafApiData.metadata.executionDate}</p>
            </div>
        </header>
        
        <div class="bg-blue-50 border border-blue-200 rounded-lg p-4 mb-6">
            <h3 class="text-sm font-semibold text-blue-800 mb-2">Audit Guidance</h3>
            <p class="text-sm text-blue-700">Review WAF configurations to ensure comprehensive web application protection, verify logging and monitoring capabilities are properly configured, and validate that rule sets provide adequate coverage against common web exploits while maintaining legitimate traffic flow.</p>
        </div>
        
        <div class="border-b border-gray-200 mb-6">
            <nav class="-mb-px flex flex-wrap space-x-6" id="waf-tabs">
                <a href="#" data-tab="waf-summary-content" class="tab-link py-3 px-1 border-b-2 border-[#eb3496] text-[#eb3496] font-semibold text-sm">Summary</a>
                <a href="#" data-tab="waf-acls-content" class="tab-link py-3 px-1 border-b-2 border-transparent text-gray-500 hover:text-gray-700 font-medium text-sm">Web ACLs (${acls.length})</a>
                <a href="#" data-tab="waf-ipsets-content" class="tab-link py-3 px-1 border-b-2 border-transparent text-gray-500 hover:text-gray-700 font-medium text-sm">IP Sets (${ip_sets.length})</a>
                <a href="#" data-tab="waf-monitoring-content" class="tab-link py-3 px-1 border-b-2 border-transparent text-gray-500 hover:text-gray-700 font-medium text-sm">Logging & Monitoring</a>
                <a href="#" data-tab="waf-sh-content" class="tab-link py-3 px-1 border-b-2 border-transparent text-gray-500 hover:text-gray-700 font-medium text-sm">Security Hub (${wafFindings.length})</a>
            </nav>
        </div>
        <div id="waf-tab-content-container">
            <div id="waf-summary-content" class="waf-tab-content">${createWafSummaryCardsHtml()}</div>
            <div id="waf-acls-content" class="waf-tab-content hidden">
                ${renderServiceDescription(serviceDescriptions.webacl)}
                ${renderWafAclsTable(acls)}
            </div>
            <div id="waf-ipsets-content" class="waf-tab-content hidden">
                ${renderServiceDescription(serviceDescriptions.ipsets)}
                ${renderWafIpSetsTable(ip_sets)}
            </div>
            <div id="waf-monitoring-content" class="waf-tab-content hidden">
                ${renderServiceDescription(serviceDescriptions.logging)}
                ${renderWafMonitoringAnalysis(acls)}
            </div>
            <div id="waf-sh-content" class="waf-tab-content hidden">${createWafSecurityHubHtml()}</div>
        </div>
    `;
    
    updateWafSummaryCards(acls, ip_sets, wafFindings);
    renderSecurityHubFindings(wafFindings, 'sh-waf-findings-container', 'No Security Hub findings related to WAF were found.');
    
    const tabsNav = container.querySelector('#waf-tabs');
    if (tabsNav) tabsNav.addEventListener('click', handleTabClick(tabsNav, '.waf-tab-content'));
}

// --- SERVICE DESCRIPTION RENDERER ---
const renderServiceDescription = (serviceInfo) => {
    return `
        <div class="bg-white border border-gray-200 rounded-lg p-6 mb-6">
            <h3 class="text-lg font-semibold text-gray-800 mb-3">${serviceInfo.title}</h3>
            <div class="space-y-3">
                <div>
                    <h4 class="text-sm font-medium text-gray-700 mb-1">Definition:</h4>
                    <p class="text-sm text-gray-600">${serviceInfo.description}</p>
                </div>
                <div>
                    <h4 class="text-sm font-medium text-gray-700 mb-1">Common Use Cases:</h4>
                    <p class="text-sm text-gray-600">${serviceInfo.useCases}</p>
                </div>
                <div class="bg-yellow-50 border border-yellow-200 rounded p-3">
                    <h4 class="text-sm font-medium text-yellow-800 mb-1">Audit Considerations:</h4>
                    <p class="text-sm text-yellow-700">${serviceInfo.auditConsiderations}</p>
                </div>
            </div>
        </div>
    `;
};

// --- Funciones internas de la vista WAF (no necesitan export porque solo se usan aquí) ---

function createWafSummaryCardsHtml() {
    return `
        <div class="grid grid-cols-1 md:grid-cols-3 gap-6 mb-8">
            <div class="bg-white border border-gray-100 p-5 rounded-xl shadow-sm">
                <p class="text-sm text-gray-500">Total Web ACLs</p>
                <p id="waf-acl-count" class="text-3xl font-bold text-[#204071] mt-2">--</p>
            </div>
            <div class="bg-white border border-gray-100 p-5 rounded-xl shadow-sm">
                <p class="text-sm text-gray-500">ACLs with Logging</p>
                <p id="waf-logging-enabled" class="text-3xl font-bold text-green-600 mt-2">--</p>
            </div>
            <div class="bg-white border border-gray-100 p-5 rounded-xl shadow-sm">
                <p class="text-sm text-gray-500">Protected Resources</p>
                <p id="waf-protected-resources" class="text-3xl font-bold text-[#204071] mt-2">--</p>
            </div>
        </div>
        <div class="bg-white border border-gray-100 p-5 rounded-xl shadow-sm mb-8">
            <h3 class="font-bold text-lg text-[#204071] mb-2">Top 5 Blocked Rules (Last 30 Days)</h3>
            <div class="h-48"><canvas id="wafTopRulesChart"></canvas></div>
        </div>`;
}

function updateWafSummaryCards(acls, ipSets, wafFindings) {
    const aclCount = acls.length;
    const loggingEnabledCount = acls.filter(acl => acl.LoggingConfiguration && Object.keys(acl.LoggingConfiguration).length > 0).length;
    document.getElementById('waf-acl-count').textContent = aclCount;
    document.getElementById('waf-logging-enabled').textContent = `${loggingEnabledCount} / ${aclCount}`;
    const protectedResources = acls.reduce((sum, acl) => sum + (acl.AssociatedResourceArns?.length || 0), 0);
    document.getElementById('waf-protected-resources').textContent = protectedResources;
    updateWafTopRulesChart(acls);
}

function updateWafTopRulesChart(acls) {
    const ctx = document.getElementById('wafTopRulesChart');
    if (!ctx) return;
    const ruleCounts = {};
    acls.forEach(acl => {
        if (acl.TopRules) {
            acl.TopRules.forEach(rule => {
                ruleCounts[rule.RuleName] = (ruleCounts[rule.RuleName] || 0) + rule.BlockedRequests;
            });
        }
    });
    const sortedRules = Object.entries(ruleCounts).sort(([, a], [, b]) => b - a).slice(0, 5);
    if (sortedRules.length === 0) {
        ctx.parentElement.innerHTML = '<div class="flex items-center justify-center h-full text-center text-gray-500"><p>No blocked requests found in the last 30 days.</p></div>';
        return;
    }
    const labels = sortedRules.map(item => item[0]);
    const data = sortedRules.map(item => item[1]);
    new Chart(ctx, {
        type: 'bar',
        data: {
            labels: labels,
            datasets: [{
                label: 'Blocked Requests',
                data: data,
                backgroundColor: 'rgba(235, 52, 150, 0.6)',
                borderColor: 'rgba(235, 52, 150, 1)',
                borderWidth: 1
            }]
        },
        options: {
            indexAxis: 'y',
            responsive: true,
            maintainAspectRatio: false,
            plugins: { legend: { display: false } },
            scales: { x: { beginAtZero: true, ticks: { precision: 0 } } }
        }
    });
}

function createWafSecurityHubHtml() {
    return `<div class="bg-white p-6 rounded-xl shadow-sm border border-gray-100"><h3 class="font-bold text-lg mb-4 text-[#204071]">Active Security Findings (WAF)</h3><div id="sh-waf-findings-container" class="overflow-x-auto"></div></div>`;
}

function renderWafAclsTable(acls) {
    if (!acls || acls.length === 0) {
        return `
            <div class="bg-white p-6 rounded-xl border border-gray-100">
                <div class="text-center">
                    <svg class="mx-auto h-12 w-12 text-gray-400" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" />
                    </svg>
                    <h3 class="mt-2 text-sm font-medium text-gray-900">No Web ACLs found</h3>
                    <p class="mt-1 text-sm text-gray-500">This account does not have WAF Web ACLs configured, which may leave web applications vulnerable to common attacks.</p>
                </div>
            </div>
        `;
    }
    
    let table = '<div class="bg-white p-6 rounded-xl shadow-sm border border-gray-100 overflow-x-auto"><table class="min-w-full divide-y divide-gray-200"><thead class="bg-gray-50"><tr><th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Name</th><th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Scope</th><th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Region</th><th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Logging Destination</th><th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Sampled Requests</th><th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Protected Resources</th></tr></thead><tbody class="bg-white divide-y divide-gray-200">';
    acls.sort((a,b) => a.Name.localeCompare(b.Name)).forEach(acl => {
        let resourcesHtml = '<span class="px-2 py-1 text-xs font-semibold rounded-full bg-red-100 text-red-800">No associated resources</span>';
        if (acl.AssociatedResourceArns && acl.AssociatedResourceArns.length > 0) {
            resourcesHtml = `<div class="flex flex-col space-y-1">` + acl.AssociatedResourceArns.map(arn => `<span class="px-2 py-1 text-xs font-semibold rounded-full bg-green-100 text-green-800 font-mono">${arn}</span>`).join('') + `</div>`;
        }
        let loggingHtml = '<span class="px-2 py-1 text-xs font-semibold rounded-full bg-gray-100 text-gray-700">Disabled</span>';
        if (acl.LoggingConfiguration && acl.LoggingConfiguration.LogDestinationConfigs && acl.LoggingConfiguration.LogDestinationConfigs.length > 0) {
            const firehoseArn = acl.LoggingConfiguration.LogDestinationConfigs[0];
            const firehoseName = firehoseArn.split('/').pop();
            loggingHtml = `<span class="px-2 py-1 text-xs font-semibold rounded-full bg-blue-100 text-blue-800 font-mono" title="${firehoseArn}">${firehoseName}</span>`;
        }
        const sampledEnabled = acl.VisibilityConfig ? acl.VisibilityConfig.SampledRequestsEnabled : false;
        const sampledBadge = sampledEnabled ? createStatusBadge('Enabled') : createStatusBadge('Disabled');
        table += `<tr class="hover:bg-gray-50"><td class="px-4 py-4 align-top whitespace-nowrap text-sm font-medium text-gray-800">${acl.Name}</td><td class="px-4 py-4 align-top whitespace-nowrap text-sm text-gray-600">${acl.Scope}</td><td class="px-4 py-4 align-top whitespace-nowrap text-sm text-gray-600">${acl.Region}</td><td class="px-4 py-4 align-top whitespace-nowrap text-sm">${loggingHtml}</td><td class="px-4 py-4 align-top whitespace-nowrap text-sm">${sampledBadge}</td><td class="px-4 py-4 align-top text-sm">${resourcesHtml}</td></tr>`;
    });
    table += '</tbody></table></div>';
    return table;
}

function renderWafIpSetsTable(ipSets) { 
    if (!ipSets || ipSets.length === 0) {
        return `
            <div class="bg-white p-6 rounded-xl border border-gray-100">
                <div class="text-center">
                    <svg class="mx-auto h-12 w-12 text-gray-400" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" />
                    </svg>
                    <h3 class="mt-2 text-sm font-medium text-gray-900">No IP Sets found</h3>
                    <p class="mt-1 text-sm text-gray-500">This account does not have WAF IP Sets configured. Consider creating IP sets for better management of allow/block lists.</p>
                </div>
            </div>
        `;
    }
    
    let table = '<div class="bg-white p-6 rounded-xl shadow-sm border border-gray-100 overflow-x-auto"><table class="min-w-full divide-y divide-gray-200"><thead class="bg-gray-50"><tr><th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Name</th><th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Scope</th><th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Region</th><th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">IP Version</th><th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase"># Addresses</th></tr></thead><tbody class="bg-white divide-y divide-gray-200">'; 
    ipSets.sort((a,b) => a.Name.localeCompare(b.Name)).forEach(ipSet => { 
        table += `<tr class="hover:bg-gray-50"><td class="px-4 py-4 whitespace-nowrap text-sm font-medium text-gray-800">${ipSet.Name}</td><td class="px-4 py-4 whitespace-nowrap text-sm text-gray-600">${ipSet.Scope}</td><td class="px-4 py-4 whitespace-nowrap text-sm text-gray-600">${ipSet.Region}</td><td class="px-4 py-4 whitespace-nowrap text-sm text-gray-600">${ipSet.IPAddressVersion}</td><td class="px-4 py-4 whitespace-nowrap text-sm text-gray-600">${ipSet.AddressCount}</td></tr>`; 
    }); 
    table += '</tbody></table></div>'; 
    return table; 
}

function renderWafMonitoringAnalysis(acls) {
    // Calculate monitoring metrics
    let totalAcls = acls.length;
    let loggingEnabled = acls.filter(acl => acl.LoggingConfiguration && Object.keys(acl.LoggingConfiguration).length > 0).length;
    let samplingEnabled = acls.filter(acl => acl.VisibilityConfig && acl.VisibilityConfig.SampledRequestsEnabled).length;
    let unprotectedAcls = acls.filter(acl => !acl.AssociatedResourceArns || acl.AssociatedResourceArns.length === 0).length;
    
    return `
        <div class="space-y-6">
            <div class="grid grid-cols-1 md:grid-cols-4 gap-4">
                <div class="bg-white border border-gray-200 rounded-lg p-4">
                    <div class="flex items-center">
                        <div class="flex-shrink-0">
                            <div class="w-8 h-8 bg-blue-100 rounded-full flex items-center justify-center">
                                <svg class="w-4 h-4 text-blue-600" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 17v-2m3 2v-4m3 4v-6m2 10H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z"></path>
                                </svg>
                            </div>
                        </div>
                        <div class="ml-3">
                            <p class="text-sm font-medium text-gray-500">Logging Coverage</p>
                            <p class="text-2xl font-semibold text-gray-900">${Math.round((loggingEnabled/totalAcls)*100) || 0}%</p>
                        </div>
                    </div>
                </div>
                
                <div class="bg-white border border-gray-200 rounded-lg p-4">
                    <div class="flex items-center">
                        <div class="flex-shrink-0">
                            <div class="w-8 h-8 bg-green-100 rounded-full flex items-center justify-center">
                                <svg class="w-4 h-4 text-green-600" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M15 12a3 3 0 11-6 0 3 3 0 016 0z"></path>
                                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M2.458 12C3.732 7.943 7.523 5 12 5c4.478 0 8.268 2.943 9.542 7-1.274 4.057-5.064 7-9.542 7-4.477 0-8.268-2.943-9.542-7z"></path>
                                </svg>
                            </div>
                        </div>
                        <div class="ml-3">
                            <p class="text-sm font-medium text-gray-500">Request Sampling</p>
                            <p class="text-2xl font-semibold text-gray-900">${Math.round((samplingEnabled/totalAcls)*100) || 0}%</p>
                        </div>
                    </div>
                </div>
                
                <div class="bg-white border border-gray-200 rounded-lg p-4">
                    <div class="flex items-center">
                        <div class="flex-shrink-0">
                            <div class="w-8 h-8 bg-purple-100 rounded-full flex items-center justify-center">
                                <svg class="w-4 h-4 text-purple-600" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z"></path>
                                </svg>
                            </div>
                        </div>
                        <div class="ml-3">
                            <p class="text-sm font-medium text-gray-500">Active Protection</p>
                            <p class="text-2xl font-semibold text-gray-900">${Math.round(((totalAcls - unprotectedAcls)/totalAcls)*100) || 0}%</p>
                        </div>
                    </div>
                </div>
                
                <div class="bg-white border border-gray-200 rounded-lg p-4">
                    <div class="flex items-center">
                        <div class="flex-shrink-0">
                            <div class="w-8 h-8 bg-orange-100 rounded-full flex items-center justify-center">
                                <svg class="w-4 h-4 text-orange-600" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-2.5L13.732 4c-.77-.833-1.964-.833-2.732 0L3.732 16.5c-.77.833.192 2.5 1.732 2.5z"></path>
                                </svg>
                            </div>
                        </div>
                        <div class="ml-3">
                            <p class="text-sm font-medium text-gray-500">Unprotected ACLs</p>
                            <p class="text-2xl font-semibold text-gray-900">${unprotectedAcls}</p>
                        </div>
                    </div>
                </div>
            </div>
            
            ${renderWafMonitoringRecommendations(acls, loggingEnabled, samplingEnabled, unprotectedAcls)}
        </div>
    `;
}

function renderWafMonitoringRecommendations(acls, loggingEnabled, samplingEnabled, unprotectedAcls) {
    const recommendations = [];
    const totalAcls = acls.length;
    
    if (totalAcls === 0) {
        recommendations.push({
            type: 'critical',
            title: 'No WAF Protection',
            message: 'No Web ACLs are configured, leaving web applications vulnerable to common attacks.',
            action: 'Implement WAF protection for all public-facing web applications and APIs.'
        });
    } else {
        if (loggingEnabled < totalAcls) {
            recommendations.push({
                type: 'warning',
                title: 'Incomplete Logging Coverage',
                message: `${totalAcls - loggingEnabled} Web ACL(s) do not have logging enabled, limiting incident response capabilities.`,
                action: 'Enable comprehensive logging for all Web ACLs and configure appropriate log retention policies.'
            });
        }
        
        if (samplingEnabled < totalAcls) {
            recommendations.push({
                type: 'info',
                title: 'Request Sampling Disabled',
                message: `${totalAcls - samplingEnabled} Web ACL(s) have request sampling disabled, reducing visibility into blocked requests.`,
                action: 'Enable request sampling for better rule analysis and tuning capabilities.'
            });
        }
        
        if (unprotectedAcls > 0) {
            recommendations.push({
                type: 'warning',
                title: 'Unattached Web ACLs',
                message: `${unprotectedAcls} Web ACL(s) are not protecting any resources.`,
                action: 'Associate Web ACLs with relevant resources or remove unused ACLs to maintain clean configuration.'
            });
        }
        
        if (recommendations.length === 0) {
            recommendations.push({
                type: 'success',
                title: 'WAF Configuration Healthy',
                message: 'All Web ACLs are properly configured with logging and monitoring enabled.',
                action: 'Continue monitoring WAF effectiveness and regularly review rule performance metrics.'
            });
        }
    }
    
    const typeColors = {
        critical: 'border-red-200 bg-red-50',
        warning: 'border-yellow-200 bg-yellow-50',
        info: 'border-blue-200 bg-blue-50',
        success: 'border-green-200 bg-green-50'
    };
    
    const typeTextColors = {
        critical: 'text-red-800',
        warning: 'text-yellow-800',
        info: 'text-blue-800',
        success: 'text-green-800'
    };
    
    const typeIcons = {
        critical: '<svg class="w-5 h-5" fill="currentColor" viewBox="0 0 20 20"><path fill-rule="evenodd" d="M18 10a8 8 0 11-16 0 8 8 0 0116 0zm-7 4a1 1 0 11-2 0 1 1 0 012 0zm-1-9a1 1 0 00-1 1v4a1 1 0 102 0V6a1 1 0 00-1-1z" clip-rule="evenodd"></path></svg>',
        warning: '<svg class="w-5 h-5" fill="currentColor" viewBox="0 0 20 20"><path fill-rule="evenodd" d="M8.257 3.099c.765-1.36 2.722-1.36 3.486 0l5.58 9.92c.75 1.334-.213 2.98-1.742 2.98H4.42c-1.53 0-2.493-1.646-1.743-2.98l5.58-9.92zM11 13a1 1 0 11-2 0 1 1 0 012 0zm-1-8a1 1 0 00-1 1v3a1 1 0 002 0V6a1 1 0 00-1-1z" clip-rule="evenodd"></path></svg>',
        info: '<svg class="w-5 h-5" fill="currentColor" viewBox="0 0 20 20"><path fill-rule="evenodd" d="M18 10a8 8 0 11-16 0 8 8 0 0116 0zm-7-4a1 1 0 11-2 0 1 1 0 012 0zM9 9a1 1 0 000 2v3a1 1 0 001 1h1a1 1 0 100-2v-3a1 1 0 00-1-1H9z" clip-rule="evenodd"></path></svg>',
        success: '<svg class="w-5 h-5" fill="currentColor" viewBox="0 0 20 20"><path fill-rule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zm3.707-9.293a1 1 0 00-1.414-1.414L9 10.586 7.707 9.293a1 1 0 00-1.414 1.414l2 2a1 1 0 001.414 0l4-4z" clip-rule="evenodd"></path></svg>'
    };
    
    return `
        <div class="bg-white border border-gray-200 rounded-lg p-6">
            <h3 class="text-lg font-semibold text-gray-800 mb-4">WAF Monitoring & Logging Recommendations</h3>
            <div class="space-y-4">
                ${recommendations.map(rec => `
                    <div class="border rounded-lg p-4 ${typeColors[rec.type]}">
                        <div class="flex items-start">
                            <div class="flex-shrink-0 ${typeTextColors[rec.type]} mt-0.5">
                                ${typeIcons[rec.type]}
                            </div>
                            <div class="ml-3 flex-1">
                                <h4 class="text-sm font-medium ${typeTextColors[rec.type]}">${rec.title}</h4>
                                <p class="text-sm ${typeTextColors[rec.type]} mt-1">${rec.message}</p>
                                <p class="text-sm ${typeTextColors[rec.type]} mt-2 font-medium">Recommended Action: ${rec.action}</p>
                            </div>
                        </div>
                    </div>
                `).join('')}
            </div>
        </div>
    `;
}