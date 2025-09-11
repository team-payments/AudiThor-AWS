/**
 * 15_config_sh.js
 * Contains all logic for building and rendering the AWS Config & Security Hub view. (CORREGIDO)
 */

// --- IMPORTS ---
import { handleTabClick, createStatusBadge, log, setupPaginationNew } from '../utils.js';


// --- MAIN VIEW FUNCTION (EXPORTED) ---
export const buildConfigSHView = () => {
    console.log('=== buildConfigSHView DEBUG ===');
    console.log('window.configSHApiData:', window.configSHApiData)
    const container = document.getElementById('config-sh-view');
    const executionDate = (window.configSHApiData || window.configSHStatusApiData)?.metadata?.executionDate || 'Analysis not run.';

    if (window.configSHApiData) {
        const results = window.configSHApiData.results || {};
        console.log('=== RESULTS DEBUG ===');
        console.log('results:', results);
        console.log('results.service_status:', results.service_status);
        console.log('results.findings:', results.findings);
        const service_status = results.service_status || [];
        
        // CORRECCIÓN: Verificar que findings existe y es un array
        let findings = results.findings || [];
        console.log('=== AFTER ASSIGNMENT DEBUG ===');
        console.log('service_status after assignment:', service_status);
        console.log('findings after assignment:', findings);
        console.log('service_status is Array:', Array.isArray(service_status));
        console.log('findings is Array:', Array.isArray(findings));
        if (!Array.isArray(findings)) {
            console.warn('Findings is not an array:', findings);
            findings = [];
        }
        
        container.innerHTML = `
            <header class="flex justify-between items-center mb-6">
                <div>
                    <h2 class="text-2xl font-bold text-[#204071]">Config & Security Hub Status</h2>
                    <p class="text-sm text-gray-500">${executionDate}</p>
                </div>
            </header>
            <div id="config-sh-results-view">
                <div class="border-b border-gray-200 mb-6">
                    <nav class="-mb-px flex flex-wrap space-x-6" id="config-sh-tabs">
                        <a href="#" data-tab="config-sh-summary-content" class="tab-link py-3 px-1 border-b-2 border-[#eb3496] text-[#eb3496] font-semibold text-sm">Summary</a>
                        <a href="#" data-tab="config-sh-status-content" class="tab-link py-3 px-1 border-b-2 border-transparent text-gray-500 hover:text-gray-700 font-medium text-sm">Service Status</a>
                        <a href="#" data-tab="config-sh-findings-content" class="tab-link py-3 px-1 border-b-2 border-transparent text-gray-500 hover:text-gray-700 font-medium text-sm">All Findings</a>
                    </nav>
                </div>
                <div id="config-sh-tab-content-container">
                    <div id="config-sh-summary-content" class="config-sh-tab-content">${createConfigSHSummaryCardsHtml()}</div>
                    <div id="config-sh-status-content" class="config-sh-tab-content hidden">${renderConfigSHStatusTable(service_status)}</div>
                    <div id="config-sh-findings-content" class="config-sh-tab-content hidden"></div>
                </div>
            </div>`;

        updateConfigSHSummaryCards(service_status, findings);
        renderAllFindingsTable(findings);
        
        const tabsNav = container.querySelector('#config-sh-tabs');
        if (tabsNav) tabsNav.addEventListener('click', handleTabClick(tabsNav, '.config-sh-tab-content'));

    } else if (window.configSHStatusApiData) {
        const results = window.configSHStatusApiData.results || {};
        const service_status = results.service_status || [];
        
        container.innerHTML = `
            <header class="flex justify-between items-center mb-6">
                <div>
                    <h2 class="text-2xl font-bold text-[#204071]">Config & Security Hub Status</h2>
                    <p class="text-sm text-gray-500">${executionDate}</p>
                </div>
            </header>
            <div class="border-b border-gray-200 mb-6">
                 <nav class="-mb-px flex flex-wrap space-x-6" id="config-sh-tabs">
                    <a href="#" data-tab="config-sh-status-content" class="tab-link py-3 px-1 border-b-2 border-[#eb3496] text-[#eb3496] font-semibold text-sm">Service Status</a>
                    <a href="#" data-tab="config-sh-deep-scan-content" class="tab-link py-3 px-1 border-b-2 border-transparent text-gray-500 hover:text-gray-700 font-medium text-sm">Deep Dive Analysis</a>
                </nav>
            </div>
            <div id="config-sh-initial-view">
                <div id="config-sh-status-content" class="config-sh-tab-content">
                    ${renderConfigSHStatusTable(service_status)}
                </div>
                <div id="config-sh-deep-scan-content" class="config-sh-tab-content hidden">
                    <div class="bg-white mt-6 p-6 rounded-xl shadow-sm border border-gray-100 text-center">
                        <p class="text-gray-600 mb-4">Run the deep analysis to view all Security Hub findings. This process may take several minutes.</p>
                        <button id="run-deep-scan-btn" class="bg-[#eb3496] text-white px-5 py-2.5 rounded-lg font-bold text-md hover:bg-[#d42c86] transition flex items-center justify-center space-x-2 mx-auto">
                            <span id="deep-scan-btn-text">Run Deep Dive Analysis</span>
                            <div id="deep-scan-spinner" class="spinner hidden"></div>
                        </button>
                    </div>
                </div>
            </div>`;
        
        const tabsNav = container.querySelector('#config-sh-tabs');
        if (tabsNav) tabsNav.addEventListener('click', handleTabClick(tabsNav, '.config-sh-tab-content'));
        
        const deepScanBtn = document.getElementById('run-deep-scan-btn');
        if (deepScanBtn) {
            deepScanBtn.addEventListener('click', runDeepConfigSHAnalysis);
        }

    } else {
         container.innerHTML = `
            <header class="flex justify-between items-center mb-6">
                <div>
                    <h2 class="text-2xl font-bold text-[#204071]">Config & Security Hub Status</h2>
                    <p class="text-sm text-gray-500">Enter credentials to see the status.</p>
                </div>
            </header>
            <p class="text-center text-gray-500 py-8">Results will appear here after the analysis.</p>
        `;
    }
};


// --- INTERNAL MODULE FUNCTIONS (NOT EXPORTED) ---
async function runDeepConfigSHAnalysis() {
    const runBtn = document.getElementById('run-deep-scan-btn');
    const btnText = document.getElementById('deep-scan-btn-text');
    const spinner = document.getElementById('deep-scan-spinner');
    
    if (!runBtn || !btnText || !spinner) {
        log('Error: Required elements not found for deep scan', 'error');
        return;
    }
    
    runBtn.disabled = true;
    spinner.classList.remove('hidden');
    btnText.textContent = 'Analyzing… (this can take a few minutes)';
    log('Starting deep analysis of Config & Security Hub…', 'info');

    const accessKeyInput = document.getElementById('access-key-input');
    const secretKeyInput = document.getElementById('secret-key-input');
    const sessionTokenInput = document.getElementById('session-token-input');

    if (!accessKeyInput || !secretKeyInput) {
        log('Error: Credential inputs not found', 'error');
        runBtn.disabled = false;
        spinner.classList.add('hidden');
        btnText.textContent = 'Run Deep Dive Analysis';
        return;
    }

    const payload = {
        access_key: accessKeyInput.value.trim(),
        secret_key: secretKeyInput.value.trim(),
        session_token: sessionTokenInput.value.trim() || null,
    };

    try {
        const response = await fetch('http://127.0.0.1:5001/api/run-config-sh-audit', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(payload)
        });

        console.log('=== RESPONSE DEBUG ===');
        console.log('Response OK:', response.ok);
        console.log('Response status:', response.status);
        
        if (!response.ok) {
            const errorData = await response.json();
            throw new Error(errorData.error || `HTTP ${response.status}`);
        }
        
        const responseData = await response.json();
        console.log('=== RESPONSE DATA DEBUG ===');
        console.log('Full response:', responseData);
        console.log('Response.results:', responseData.results);
        console.log('Response.results type:', typeof responseData.results);
        
        // CORRECCIÓN: Validar la estructura de la respuesta
        if (!responseData || !responseData.results) {
            console.log('service_status:', responseData.results.service_status);
            console.log('service_status type:', typeof responseData.results.service_status);
            console.log('findings:', responseData.results.findings);
            console.log('findings type:', typeof responseData.results.findings);
            throw new Error('Invalid response structure from deep scan API');
        }
        
        window.configSHApiData = responseData;
        
        log('Deep analysis of Config & Security Hub completed.', 'success');
        
        // Log para debug
        console.log('Deep scan response:', responseData);
        console.log('Service status:', responseData.results?.service_status);
        console.log('Findings:', responseData.results?.findings);
        
        buildConfigSHView();

        if (window.runAndDisplayHealthyStatus) {
            window.runAndDisplayHealthyStatus();
        }

    } catch (e) {
        log(`Error in deep analysis: ${e.message}`, 'error');
        console.error('Deep scan error details:', e);
        
        const initialContainer = document.getElementById('config-sh-initial-view');
        if(initialContainer) {
            initialContainer.innerHTML = `
                <div class="bg-red-50 text-red-700 p-4 rounded-lg">
                    <h4 class="font-bold">Error</h4>
                    <p>${e.message}</p>
                </div>`;
        }
    } finally {
        runBtn.disabled = false;
        spinner.classList.add('hidden');
        btnText.textContent = 'Run Deep Dive Analysis';
    }
}

function createConfigSHSummaryCardsHtml() {
    return `
    <div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-5 mb-8">
        <div class="bg-white border border-gray-100 p-5 rounded-xl shadow-sm flex flex-col justify-between h-full">
            <div><p class="text-sm text-gray-500">Regions with Config</p></div>
            <div class="flex justify-between items-end pt-4"><p id="config-sh-config-enabled" class="text-3xl font-bold text-[#204071]">--</p><div class="bg-blue-100 p-3 rounded-full"><svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" fill="currentColor" class="bi bi-ui-checks w-6 h-6 text-blue-600" viewBox="0 0 16 16"><path d="M7 2.5a.5.5 0 0 1 .5-.5h7a.5.5 0 0 1 .5.5v1a.5.5 0 0 1-.5.5h-7a.5.5 0 0 1-.5-.5zM2 1a2 2 0 0 0-2 2v2a2 2 0 0 0 2 2h2a2 2 0 0 0 2-2V3a2 2 0 0 0-2-2zm0 8a2 2 0 0 0-2 2v2a2 2 0 0 0 2 2h2a2 2 0 0 0 2-2v-2a2 2 0 0 0-2-2zm.854-3.646a.5.5 0 0 1-.708 0l-1-1a.5.5 0 1 1 .708-.708l.646.647 1.646-1.647a.5.5 0 1 1 .708.708zm0 8a.5.5 0 0 1-.708 0l-1-1a.5.5 0 0 1 .708-.708l.646.647 1.646-1.647a.5.5 0 0 1 .708.708zM7 10.5a.5.5 0 0 1 .5-.5h7a.5.5 0 0 1 .5.5v1a.5.5 0 0 1-.5.5h-7a.5.5 0 0 1-.5-.5zm0-5a.5.5 0 0 1 .5-.5h5a.5.5 0 0 1 0 1h-5a.5.5 0 0 1-.5-.5m0 8a.5.5 0 0 1 .5-.5h5a.5.5 0 0 1 0 1h-5a.5.5 0 0 1-.5-.5"/></svg></div>
            </div>
        </div>
        <div class="bg-white border border-gray-100 p-5 rounded-xl shadow-sm flex flex-col justify-between h-full">
            <div><p class="text-sm text-gray-500">Regions with Security Hub</p></div>
            <div class="flex justify-between items-end pt-4"><p id="config-sh-sh-enabled" class="text-3xl font-bold text-[#204071]">--</p><div class="bg-green-100 p-3 rounded-full"><svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" fill="currentColor" class="bi bi-ui-checks w-6 h-6 text-green-600" viewBox="0 0 16 16"><path d="M7 2.5a.5.5 0 0 1 .5-.5h7a.5.5 0 0 1 .5.5v1a.5.5 0 0 1-.5.5h-7a.5.5 0 0 1-.5-.5zM2 1a2 2 0 0 0-2 2v2a2 2 0 0 0 2 2h2a2 2 0 0 0 2-2V3a2 2 0 0 0-2-2zm0 8a2 2 0 0 0-2 2v2a2 2 0 0 0 2 2h2a2 2 0 0 0 2-2v-2a2 2 0 0 0-2-2zm.854-3.646a.5.5 0 0 1-.708 0l-1-1a.5.5 0 1 1 .708-.708l.646.647 1.646-1.647a.5.5 0 1 1 .708.708zm0 8a.5.5 0 0 1-.708 0l-1-1a.5.5 0 0 1 .708-.708l.646.647 1.646-1.647a.5.5 0 0 1 .708.708zM7 10.5a.5.5 0 0 1 .5-.5h7a.5.5 0 0 1 .5.5v1a.5.5 0 0 1-.5.5h-7a.5.5 0 0 1-.5-.5zm0-5a.5.5 0 0 1 .5-.5h5a.5.5 0 0 1 0 1h-5a.5.5 0 0 1-.5-.5m0 8a.5.5 0 0 1 .5-.5h5a.5.5 0 0 1 0 1h-5a.5.5 0 0 1-.5-.5"/></svg></div>
            </div>
        </div>
        <div class="bg-white border border-gray-100 p-5 rounded-xl shadow-sm flex flex-col justify-between h-full">
            <div><p class="text-sm text-gray-500">Total Active Findings</p></div>
            <div class="flex justify-between items-end pt-4"><p id="config-sh-total-findings" class="text-3xl font-bold text-[#204071]">--</p><div class="bg-orange-100 p-3 rounded-full"><svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" fill="currentColor" class="bi bi-shield-exclamation w-6 h-6 text-orange-600" viewBox="0 0 16 16"><path d="M5.338 1.59a61 61 0 0 0-2.837.856.48.48 0 0 0-.328.39c-.554 4.157.726 7.19 2.253 9.188a10.7 10.7 0 0 0 2.287 2.233c.346.244.652.42.893.533q.18.085.293.118a1 1 0 0 0 .101.025 1 1 0 0 0 .1-.025q.114-.034.294-.118c.24-.113.547-.29.893-.533a10.7 10.7 0 0 0 2.287-2.233c1.527-1.997 2.807-5.031 2.253-9.188a.48.48 0 0 0-.328-.39c-.651-.213-1.75-.56-2.837-.855C9.552 1.29 8.531 1.067 8 1.067c-.53 0-1.552.223-2.662.524zM5.072.56C6.157.265 7.31 0 8 0s1.843.265 2.928.56c1.11.3 2.229.655 2.887.87a1.54 1.54 0 0 1 1.044 1.262c.596 4.477-.787 7.795-2.465 9.99a11.8 11.8 0 0 1-2.517 2.453 7 7 0 0 1-1.048.625c-.28.132-.581.24-.829.24s-.548-.108-.829-.24a7 7 0 0 1-1.048-.625 11.8 11.8 0 0 1-2.517-2.453C1.928 10.487.545 7.169 1.141 2.692A1.54 1.54 0 0 1 2.185 1.43 63 63 0 0 1 5.072.56"/><path d="M7.001 11a1 1 0 1 1 2 0 1 1 0 0 1-2 0M7.1 4.995a.905.905 0 1 1 1.8 0l-.35 3.507a.553.553 0 0 1-1.1 0z"/></svg></div>
            </div>
        </div>
        <div class="bg-white border border-gray-100 p-5 rounded-xl shadow-sm flex flex-col justify-between h-full">
            <div><p class="text-sm text-gray-500">Critical / High Findings</p></div>
            <div class="flex justify-between items-end pt-4"><p id="config-sh-critical-findings" class="text-3xl font-bold text-red-600">--</p><div class="bg-red-100 p-3 rounded-full"><svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" fill="currentColor" class="bi bi-shield-exclamation w-6 h-6 text-red-600" viewBox="0 0 16 16"><path d="M5.338 1.59a61 61 0 0 0-2.837.856.48.48 0 0 0-.328.39c-.554 4.157.726 7.19 2.253 9.188a10.7 10.7 0 0 0 2.287 2.233c.346.244.652.42.893.533q.18.085.293.118a1 1 0 0 0 .101.025 1 1 0 0 0 .1-.025q.114-.034.294-.118c.24-.113.547-.29.893-.533a10.7 10.7 0 0 0 2.287-2.233c1.527-1.997 2.807-5.031 2.253-9.188a.48.48 0 0 0-.328-.39c-.651-.213-1.75-.56-2.837-.855C9.552 1.29 8.531 1.067 8 1.067c-.53 0-1.552.223-2.662.524zM5.072.56C6.157.265 7.31 0 8 0s1.843.265 2.928.56c1.11.3 2.229.655 2.887.87a1.54 1.54 0 0 1 1.044 1.262c.596 4.477-.787 7.795-2.465 9.99a11.8 11.8 0 0 1-2.517 2.453 7 7 0 0 1-1.048.625c-.28.132-.581.24-.829.24s-.548-.108-.829-.24a7 7 0 0 1-1.048-.625 11.8 11.8 0 0 1-2.517-2.453C1.928 10.487.545 7.169 1.141 2.692A1.54 1.54 0 0 1 2.185 1.43 63 63 0 0 1 5.072.56"/><path d="M7.001 11a1 1 0 1 1 2 0 1 1 0 0 1-2 0M7.1 4.995a.905.905 0 1 1 1.8 0l-.35 3.507a.553.553 0 0 1-1.1 0z"/></svg></div>
            </div>
        </div>
    </div>
    `;
}

function updateConfigSHSummaryCards(serviceStatus = [], findings = []) {
    // CORRECCIÓN: Validar que los parámetros son arrays
    if (!Array.isArray(serviceStatus)) {
        console.warn('serviceStatus is not an array:', serviceStatus);
        serviceStatus = [];
    }
    if (!Array.isArray(findings)) {
        console.warn('findings is not an array:', findings);
        findings = [];
    }
    
    const totalRegions = serviceStatus.length;
    const configEnabledCount = serviceStatus.filter(s => s.ConfigEnabled).length;
    const shEnabledCount = serviceStatus.filter(s => s.SecurityHubEnabled).length;
    const criticalHighCount = findings.filter(f => {
        const severity = f.Severity?.Label;
        return severity && ['CRITICAL', 'HIGH'].includes(severity);
    }).length;

    const configElement = document.getElementById('config-sh-config-enabled');
    const shElement = document.getElementById('config-sh-sh-enabled');
    const totalElement = document.getElementById('config-sh-total-findings');
    const criticalElement = document.getElementById('config-sh-critical-findings');

    if (configElement) configElement.textContent = `${configEnabledCount} / ${totalRegions}`;
    if (shElement) shElement.textContent = `${shEnabledCount} / ${totalRegions}`;
    if (totalElement) totalElement.textContent = findings.length;
    if (criticalElement) criticalElement.textContent = criticalHighCount;
}

function renderConfigSHStatusTable(serviceStatus = []) {
    // CORRECCIÓN: Validar que serviceStatus es un array
    if (!Array.isArray(serviceStatus)) {
        console.warn('serviceStatus is not an array:', serviceStatus);
        serviceStatus = [];
    }
    
    if (serviceStatus.length === 0) {
        return '<div class="bg-white p-6 rounded-xl border border-gray-100"><p class="text-center text-gray-500">Service status could not be retrieved by region.</p></div>';
    }

    const activeRegions = serviceStatus.filter(s => s.ConfigEnabled || s.SecurityHubEnabled);
    if (activeRegions.length === 0) {
        return '<div class="bg-white p-6 rounded-xl border border-gray-100"><p class="text-center text-gray-500">No regions with AWS Config or Security Hub enabled.</p></div>';
    }
    
    let tableHtml = '<div class="bg-white p-6 rounded-xl shadow-sm border border-gray-100 overflow-x-auto"><table class="min-w-full divide-y divide-gray-200"><thead class="bg-gray-50"><tr>' +
                    '<th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Region</th>' +
                    '<th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">AWS Config</th>' +
                    '<th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">AWS Security Hub</th>' +
                    '<th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Security Hub Standards</th>' +
                    '<th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Conformance Packs</th>' +
                    '</tr></thead><tbody class="bg-white divide-y divide-gray-200">';
    
    activeRegions.forEach(s => {
        const configBadge = s.ConfigEnabled ? createStatusBadge('Enabled') : createStatusBadge('Disabled');
        const shBadge = s.SecurityHubEnabled ? createStatusBadge('Enabled') : createStatusBadge('Disabled');
        
        let standardsHtml = '-';
        if (s.EnabledStandards && Array.isArray(s.EnabledStandards) && s.EnabledStandards.length > 0) {
            standardsHtml = '<div class="flex flex-col items-start gap-1">' + 
                            s.EnabledStandards.map(arn => {
                                const shortName = arn.split(/[/:]standards\//).pop() || arn;
                                return `<span class="px-2 py-1 text-xs font-semibold rounded-full bg-blue-100 text-blue-800">${shortName}</span>`
                            }).join('') +
                            '</div>';
        }
        
        let conformancePacksHtml = '-';
        if (s.EnabledConformancePacks && Array.isArray(s.EnabledConformancePacks) && s.EnabledConformancePacks.length > 0) {
            conformancePacksHtml = '<div class="flex flex-col items-start gap-1">' +
                                s.EnabledConformancePacks.map(cp => `<span class="px-2 py-1 text-xs font-semibold rounded-full bg-gray-200 text-gray-800">${cp}</span>`).join('') +
                                '</div>';
        }

        tableHtml += `<tr class="hover:bg-gray-50">
                        <td class="px-4 py-4 align-top whitespace-nowrap text-sm font-medium text-gray-800">${s.Region || 'Unknown'}</td>
                        <td class="px-4 py-4 align-top whitespace-nowrap text-sm">${configBadge}</td>
                        <td class="px-4 py-4 align-top whitespace-nowrap text-sm">${shBadge}</td>
                        <td class="px-4 py-4 align-top text-sm">${standardsHtml}</td>
                        <td class="px-4 py-4 align-top text-sm">${conformancePacksHtml}</td> 
                    </tr>`;
    });
    tableHtml += '</tbody></table></div>';
    return tableHtml;
}

function renderAllFindingsTable(findings = []) {
    const container = document.getElementById('config-sh-findings-content');
    if (!container) return;

    if (!Array.isArray(findings)) {
        console.warn('findings is not an array:', findings);
        findings = [];
    }

    const filteredFindings = findings.filter(f => {
        const isInspectorFinding = (f.GeneratorId || '').includes('inspector') || (f.ProductName || '').toLowerCase() === 'inspector';
        const hasValidStatus = f.Compliance && (f.Compliance.Status === 'PASSED' || f.Compliance.Status === 'FAILED');
        return !isInspectorFinding && hasValidStatus;
    });

    if (filteredFindings.length === 0) {
        container.innerHTML = `<div class="bg-white p-6 rounded-xl border border-gray-100"><p class="text-center text-gray-500">No Security Hub compliance findings (PASSED/FAILED) were found.</p></div>`;
        return;
    }

    const getResourceType = (finding) => {
        const resourceType = finding.Resources?.[0]?.Type;
        if (resourceType) {
            const typeMapping = {
                'AwsEc2Instance': 'EC2 Instance', 'AwsS3Bucket': 'S3 Bucket', 'AwsEc2SecurityGroup': 'Security Group',
                'AwsIamRole': 'IAM Role', 'AwsIamUser': 'IAM User', 'AwsIamPolicy': 'IAM Policy', 'AwsLambdaFunction': 'Lambda Function',
                'AwsEc2Vpc': 'VPC', 'AwsEc2Subnet': 'Subnet', 'AwsElbv2LoadBalancer': 'Load Balancer', 'AwsElbLoadBalancer': 'Classic Load Balancer',
                'AwsRdsDbInstance': 'RDS Instance', 'AwsRdsDbCluster': 'RDS Cluster', 'AwsCloudFrontDistribution': 'CloudFront',
                'AwsApiGatewayRestApi': 'API Gateway', 'AwsKmsKey': 'KMS Key', 'AwsSecretsManagerSecret': 'Secrets Manager',
                'AwsEcsCluster': 'ECS Cluster', 'AwsEksCluster': 'EKS Cluster', 'AwsSnsSubscription': 'SNS', 'AwsSqsQueue': 'SQS Queue',
                'AwsCloudTrailTrail': 'CloudTrail', 'AwsCloudWatchAlarm': 'CloudWatch', 'AwsAutoScalingGroup': 'Auto Scaling',
                'AwsConfigConfigurationRecorder': 'Config', 'AwsGuardDutyDetector': 'GuardDuty', 'AwsWafWebAcl': 'WAF',
                'AwsCodeBuildProject': 'CodeBuild', 'AwsCodePipelinePipeline': 'CodePipeline', 'AwsRedshiftCluster': 'Redshift',
                'AwsElasticSearchDomain': 'OpenSearch', 'AwsBackupBackupVault': 'Backup Vault', 'AwsEcrRepository': 'ECR Repository'
            };
            const mappedType = typeMapping[resourceType];
            if (mappedType) return mappedType;
            return resourceType.replace(/^Aws/, '').replace(/([A-Z])/g, ' $1').trim();
        }
        const resourceId = finding.Resources?.[0]?.Id || '';
        if (resourceId.includes(':instance/')) return 'EC2 Instance'; if (resourceId.includes(':bucket/')) return 'S3 Bucket';
        if (resourceId.includes(':security-group/')) return 'Security Group'; if (resourceId.includes(':role/')) return 'IAM Role';
        if (resourceId.includes(':user/')) return 'IAM User'; if (resourceId.includes(':policy/')) return 'IAM Policy';
        if (resourceId.includes(':function/')) return 'Lambda Function';
        return 'Other';
    };

    const uniqueValues = {
        severities: [...new Set(filteredFindings.map(f => f.Severity?.Label).filter(Boolean))],
        regions: [...new Set(filteredFindings.map(f => f.Region).filter(Boolean))],
        frameworks: [...new Set(filteredFindings.map(f => {
            if (f.ProductFields && f.ProductFields['StandardsArn']) {
                const standardsArn = f.ProductFields['StandardsArn'];
                if (standardsArn.includes('pci-dss')) return 'PCI DSS';
                if (standardsArn.includes('aws-foundational-security-best-practices')) return 'AWS FSBP';
                if (standardsArn.includes('cis')) return 'CIS';
                if (standardsArn.includes('nist')) return 'NIST';
                return 'Other Standard';
            } else if (f.ProductName) {
                return f.ProductName;
            }
            return null;
        }).filter(Boolean))],
        resourceTypes: [...new Set(filteredFindings.map(f => getResourceType(f)).filter(Boolean))]
    };

    uniqueValues.severities.sort((a, b) => {
        const order = { "CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFORMATIONAL": 4 };
        return (order[a] || 99) - (order[b] || 99);
    });
    uniqueValues.regions.sort();
    uniqueValues.frameworks.sort();
    uniqueValues.resourceTypes.sort();

    const severityOrder = { "CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFORMATIONAL": 4 };
    filteredFindings.sort((a, b) => {
        const severityA = severityOrder[a.Severity?.Label] ?? 99;
        const severityB = severityOrder[b.Severity?.Label] ?? 99;
        return severityA - severityB;
    });

    const applyFilters = () => {
        const statusFilter = document.getElementById('status-filter').value;
        const severityFilter = document.getElementById('severity-filter').value;
        const regionFilter = document.getElementById('region-filter').value;
        const frameworkFilter = document.getElementById('framework-filter').value;
        const resourceFilter = document.getElementById('resource-filter').value;
        const searchFilter = document.getElementById('search-filter').value.toLowerCase();

        const rows = document.querySelectorAll('#config-sh-findings-tbody .finding-row');
        let visibleCount = 0;

        rows.forEach((row, index) => {
            const finding = filteredFindings[index];
            let shouldShow = true;
            
            if (statusFilter && finding.Compliance?.Status !== statusFilter) { shouldShow = false; }
            if (severityFilter && finding.Severity?.Label !== severityFilter) { shouldShow = false; }
            if (regionFilter && finding.Region !== regionFilter) { shouldShow = false; }
            if (resourceFilter && getResourceType(finding) !== resourceFilter) { shouldShow = false; }

            if (frameworkFilter) {
                let findingFramework = null;
                if (finding.ProductFields && finding.ProductFields['StandardsArn']) {
                    const sa = finding.ProductFields['StandardsArn'];
                    if (sa.includes('pci-dss')) findingFramework = 'PCI DSS';
                    else if (sa.includes('aws-foundational-security-best-practices')) findingFramework = 'AWS FSBP';
                    else if (sa.includes('cis')) findingFramework = 'CIS';
                    else if (sa.includes('nist')) findingFramework = 'NIST';
                    else findingFramework = 'Other Standard';
                } else if (finding.ProductName) {
                    findingFramework = finding.ProductName;
                }
                if (findingFramework !== frameworkFilter) {
                    shouldShow = false;
                }
            }

            if (searchFilter) {
                const title = (finding.Title || '').toLowerCase();
                const resourceId = (finding.Resources?.[0]?.Id || '').toLowerCase();
                if (!title.includes(searchFilter) && !resourceId.includes(searchFilter)) { shouldShow = false; }
            }

            row.style.display = shouldShow ? '' : 'none';
            if (shouldShow) visibleCount++;
        });
        
        // --- CÓDIGO CORREGIDO: AÑADIDO EL BLOQUE PARA ACTUALIZAR EL CONTADOR ---
        const countDisplay = document.getElementById('findings-count-display-sh');
        if (countDisplay) {
            const totalFindings = filteredFindings.length;
            if (visibleCount === totalFindings) {
                countDisplay.innerHTML = `
                    <div class="flex items-center space-x-1">
                        <svg class="w-4 h-4" fill="currentColor" viewBox="0 0 20 20"><path fill-rule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zm3.707-9.293a1 1 0 00-1.414-1.414L9 10.586 7.707 9.293a1 1 0 00-1.414 1.414l2 2a1 1 0 001.414 0l4-4z" clip-rule="evenodd"></path></svg>
                        <span>${totalFindings} finding${totalFindings !== 1 ? 's' : ''}</span>
                    </div>`;
                countDisplay.className = "bg-[#eb3496] text-white px-3 py-1 rounded-full text-sm font-semibold flex items-center";
            } else {
                countDisplay.innerHTML = `
                    <div class="flex items-center space-x-1">
                        <svg class="w-4 h-4" fill="currentColor" viewBox="0 0 20 20"><path fill-rule="evenodd" d="M3 3a1 1 0 011-1h12a1 1 0 011 1v3a1 1 0 01-.293.707L12 11.414V15a1 1 0 01-.293.707l-2 2A1 1 0 018 17v-5.586L3.293 6.707A1 1 0 013 6V3z" clip-rule="evenodd"></path></svg>
                        <span>${visibleCount}/${totalFindings}</span>
                    </div>`;
                countDisplay.className = "bg-blue-500 text-white px-3 py-1 rounded-full text-sm font-semibold flex items-center animate-pulse";
            }
        }
        // --- FIN DE LA CORRECCIÓN ---
    };

    let tableRowsHtml = filteredFindings.map(f => {
        const severity = f.Severity?.Label || 'N/A';
        const title = f.Title || 'No Title';
        const region = f.Region || 'Global';
        const resourceId = f.Resources?.[0]?.Id || 'N/A';
        const status = f.Compliance?.Status || 'N/A';
        
        let framework = 'N/A';
        if (f.ProductFields && f.ProductFields['StandardsArn']) {
            const sa = f.ProductFields['StandardsArn'];
            if (sa.includes('pci-dss')) framework = 'PCI DSS';
            else if (sa.includes('aws-foundational-security-best-practices')) framework = 'AWS FSBP';
            else if (sa.includes('cis')) framework = 'CIS';
            else if (sa.includes('nist')) framework = 'NIST';
            else framework = 'Other Standard';
        } else if (f.ProductName) {
            framework = f.ProductName;
        }
        
        const severityBadgeColor = {
            'CRITICAL': 'bg-red-100 text-red-800', 'HIGH': 'bg-orange-100 text-orange-800',
            'MEDIUM': 'bg-yellow-100 text-yellow-800', 'LOW': 'bg-blue-100 text-blue-800',
            'INFORMATIONAL': 'bg-gray-100 text-gray-800'
        }[severity] || 'bg-gray-100 text-gray-800';

        const statusBadgeColor = {
            'PASSED': 'bg-green-100 text-green-800',
            'FAILED': 'bg-red-100 text-red-800'
        }[status] || 'bg-gray-100 text-gray-800';

        return `
            <tr class="finding-row hover:bg-gray-50">
                <td class="px-4 py-3 align-top"><span class="px-2.5 py-1 text-xs font-bold rounded-full ${severityBadgeColor}">${severity}</span></td>
                <td class="px-4 py-3 align-top text-sm font-medium text-gray-800">${title}</td>
                <td class="px-4 py-3 align-top text-sm text-gray-600">${region}</td>
                <td class="px-4 py-3 align-top text-sm text-gray-600 break-all">${resourceId}</td>
                <td class="px-4 py-3 align-top text-sm text-gray-600">
                    <span class="px-2 py-1 text-xs font-medium rounded-md bg-blue-50 text-blue-700">${framework}</span>
                </td>
                <td class="px-4 py-3 align-top"><span class="px-2.5 py-1 text-xs font-bold rounded-full ${statusBadgeColor}">${status}</span></td>
            </tr>`;
    }).join('');

    container.innerHTML = `
        <div class="bg-white p-6 rounded-xl shadow-sm border border-gray-100 overflow-x-auto">
            <div class="bg-gradient-to-r from-white to-gray-50 p-6 rounded-2xl border border-gray-200 shadow-sm mb-6">
                <div class="flex items-center justify-between mb-4">
                     <div class="flex items-center space-x-2">
                        <svg xmlns="http://www.w3.org/2000/svg" fill="currentColor" class="w-5 h-5 text-[#eb3496]" viewBox="0 0 16 16">
                            <path d="M6 10.5a.5.5 0 0 1 .5-.5h3a.5.5 0 0 1 0 1h-3a.5.5 0 0 1-.5-.5m-2-3a.5.5 0 0 1 .5-.5h7a.5.5 0 0 1 0 1h-7a.5.5 0 0 1-.5-.5m-2-3a.5.5 0 0 1 .5-.5h11a.5.5 0 0 1 0 1h-11a.5.5 0 0 1-.5-.5"/>
                        </svg>
                        <h3 class="text-lg font-bold text-gray-800">Filter Options</h3>
                    </div>
                    <div id="findings-count-display-sh" class="bg-[#eb3496] text-white px-3 py-1 rounded-full text-sm font-semibold"></div>
                </div>
                <div class="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-6 gap-4 mb-4">
                    
                    <div class="group">
                        <label class="flex items-center text-sm font-semibold text-gray-700 mb-2">
                            <svg xmlns="http://www.w3.org/2000/svg" fill="currentColor" class="w-4 h-4 mr-1 text-gray-500" viewBox="0 0 16 16">
                                <path d="M8 15A7 7 0 1 1 8 1a7 7 0 0 1 0 14m0 1A8 8 0 1 0 8 0a8 8 0 0 0 0 16"/>
                                <path d="m10.97 4.97-.02.022-3.473 4.425-2.093-2.094a.75.75 0 0 0-1.06 1.06L6.97 11.03a.75.75 0 0 0 1.079-.02l3.992-4.99a.75.75 0 0 0-1.071-1.05"/>
                            </svg>
                            Status
                        </label>
                        <select id="status-filter" class="w-full px-4 py-2.5 text-sm border-2 border-gray-200 rounded-xl focus:outline-none focus:ring-2 focus:ring-[#eb3496] focus:border-[#eb3496] transition-all duration-200 bg-white hover:border-gray-300">
                            <option value="">All Statuses</option>
                            <option value="FAILED">Failed</option>
                            <option value="PASSED">Passed</option>
                        </select>
                    </div>

                    <div class="group">
                        <label class="flex items-center text-sm font-semibold text-gray-700 mb-2">
                             <svg xmlns="http://www.w3.org/2000/svg" fill="currentColor" class="w-4 h-4 mr-1 text-red-500" viewBox="0 0 16 16">
                                <path d="M7.938 2.016A.13.13 0 0 1 8.002 2a.13.13 0 0 1 .063.016.15.15 0 0 1 .054.057l6.857 11.667c.036.06.035.124.002.183a.2.2 0 0 1-.054.06.1.1 0 0 1-.066-.017H1.146a.1.1 0 0 1-.066-.017.2.2 0 0 1-.054-.06.18.18 0 0 1 .002-.183L7.884 2.073a.15.15 0 0 1 .054-.057m1.044-.45a1.13 1.13 0 0 0-1.96 0L.165 13.233c-.457.778.091 1.767.98 1.767h13.713c.889 0 1.438-.99.98-1.767z"/>
                                <path d="M7.002 12a1 1 0 1 1 2 0 1 1 0 0 1-2 0M7.1 5.995a.905.905 0 1 1 1.8 0l-.35 3.507a.552.552 0 0 1-1.1 0z"/>
                            </svg>
                            Severity
                        </label>
                        <select id="severity-filter" class="w-full px-4 py-2.5 text-sm border-2 border-gray-200 rounded-xl focus:outline-none focus:ring-2 focus:ring-[#eb3496] focus:border-[#eb3496] transition-all duration-200 bg-white hover:border-gray-300">
                            <option value="">All Severities</option>
                            ${uniqueValues.severities.map(s => `<option value="${s}">${s}</option>`).join('')}
                        </select>
                    </div>
                    
                    <div class="group">
                        <label class="flex items-center text-sm font-semibold text-gray-700 mb-2">
                             <svg xmlns="http://www.w3.org/2000/svg" fill="currentColor" class="w-4 h-4 mr-1 text-blue-500" viewBox="0 0 16 16">
                                <path d="M12.166 8.94c-.524 1.062-1.234 2.12-1.96 3.07A32 32 0 0 1 8 14.58a32 32 0 0 1-2.206-2.57c-.726-.95-1.436-2.008-1.96-3.07C3.304 7.867 3 6.862 3 6a5 5 0 0 1 10 0c0 .862-.305 1.867-.834 2.94M8 16s6-5.686 6-10A6 6 0 0 0 2 6c0 4.314 6 10 6 10"/>
                                <path d="M8 8a2 2 0 1 1 0-4 2 2 0 0 1 0 4m0 1a3 3 0 1 0 0-6 3 3 0 0 0 0 6"/>
                            </svg>
                            Region
                        </label>
                        <select id="region-filter" class="w-full px-4 py-2.5 text-sm border-2 border-gray-200 rounded-xl focus:outline-none focus:ring-2 focus:ring-[#eb3496] focus:border-[#eb3496] transition-all duration-200 bg-white hover:border-gray-300">
                            <option value="">All Regions</option>
                            ${uniqueValues.regions.map(r => `<option value="${r}">${r}</option>`).join('')}
                        </select>
                    </div>

                    <div class="group">
                        <label class="flex items-center text-sm font-semibold text-gray-700 mb-2">
                            <svg xmlns="http://www.w3.org/2000/svg" fill="currentColor" class="w-4 h-4 mr-1 text-green-500" viewBox="0 0 16 16">
                                <path d="M10 13.5a.5.5 0 0 0 .5.5h1a.5.5 0 0 0 .5-.5v-6a.5.5 0 0 0-.5-.5h-1a.5.5 0 0 0-.5.5zm-2.5.5a.5.5 0 0 1-.5-.5v-4a.5.5 0 0 1 .5-.5h1a.5.5 0 0 1 .5.5v4a.5.5 0 0 1-.5-.5zm-3 0a.5.5 0 0 1-.5-.5v-2a.5.5 0 0 1 .5-.5h1a.5.5 0 0 1 .5.5v2a.5.5 0 0 1-.5.5z"/>
                                <path d="M14 14V4.5L9.5 0H4a2 2 0 0 0-2 2v12a2 2 0 0 0 2 2h8a2 2 0 0 0 2-2M9.5 3A1.5 1.5 0 0 0 11 4.5h2V14a1 1 0 0 1-1 1H4a1 1 0 0 1-1-1V2a1 1 0 0 1 1-1h5.5z"/>
                            </svg>
                            Framework
                        </label>
                        <select id="framework-filter" class="w-full px-4 py-2.5 text-sm border-2 border-gray-200 rounded-xl focus:outline-none focus:ring-2 focus:ring-[#eb3496] focus:border-[#eb3496] transition-all duration-200 bg-white hover:border-gray-300">
                            <option value="">All Frameworks</option>
                            ${uniqueValues.frameworks.map(f => `<option value="${f}">${f}</option>`).join('')}
                        </select>
                    </div>
                    
                    <div class="group">
                        <label class="flex items-center text-sm font-semibold text-gray-700 mb-2">
                             <svg xmlns="http://www.w3.org/2000/svg" fill="currentColor" class="w-4 h-4 mr-1 text-purple-500" viewBox="0 0 16 16">
                                <path d="M8.186 1.113a.5.5 0 0 0-.372 0L1.846 3.5 8 5.961 14.154 3.5zM15 4.239l-6.5 2.6v7.922l6.5-2.6V4.24zM7.5 14.762V6.838L1 4.239v7.923zM7.443.184a1.5 1.5 0 0 1 1.114 0l7.129 2.852A.5.5 0 0 1 16 3.5v8.662a1 1 0 0 1-.629.928l-7.185 2.874a.5.5 0 0 1-.372 0L.63 13.09a1 1 0 0 1-.63-.928V3.5a.5.5 0 0 1 .314-.464z"/>
                            </svg>
                            Resource Type
                        </label>
                        <select id="resource-filter" class="w-full px-4 py-2.5 text-sm border-2 border-gray-200 rounded-xl focus:outline-none focus:ring-2 focus:ring-[#eb3496] focus:border-[#eb3496] transition-all duration-200 bg-white hover:border-gray-300">
                            <option value="">All Resources</option>
                            ${uniqueValues.resourceTypes.map(r => `<option value="${r}">${r}</option>`).join('')}
                        </select>
                    </div>

                    <div class="group">
                         <label class="flex items-center text-sm font-semibold text-gray-700 mb-2">
                             <svg xmlns="http://www.w3.org/2000/svg" fill="currentColor" class="w-4 h-4 mr-1 text-gray-500" viewBox="0 0 16 16">
                                <path d="M11.742 10.344a6.5 6.5 0 1 0-1.397 1.398h-.001q.044.06.098.115l3.85 3.85a1 1 0 0 0 1.415-1.414l-3.85-3.85a1 1 0 0 0-.115-.1zM12 6.5a5.5 5.5 0 1 1-11 0 5.5 5.5 0 0 1 11 0"/>
                            </svg>
                            Search
                        </label>
                        <input type="text" id="search-filter" placeholder="Title or resource ID..." class="w-full px-4 py-2.5 text-sm border-2 border-gray-200 rounded-xl focus:outline-none focus:ring-2 focus:ring-[#eb3496] focus:border-[#eb3496] transition-all duration-200 bg-white hover:border-gray-300">
                    </div>
                </div>
                <div class="flex justify-between items-center pt-4 border-t border-gray-200">
                     <button id="clear-filters" class="inline-flex items-center px-4 py-2 text-sm font-medium text-[#eb3496] bg-pink-50 border border-pink-200 rounded-xl hover:bg-pink-100 hover:border-[#eb3496] transition-all duration-200 group">
                        <svg class="w-4 h-4 mr-2 group-hover:rotate-180 transition-transform duration-300" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15"></path></svg>
                        Clear All Filters
                    </button>
                    <div class="flex items-center space-x-2 text-sm text-gray-600">
                        <svg class="w-4 h-4 text-gray-400" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 5H7a2 2 0 00-2 2v12a2 2 0 002 2h10a2 2 0 002-2V7a2 2 0 00-2-2h-2M9 5a2 2 0 002 2h2a2 2 0 002-2M9 5a2 2 0 012-2h2a2 2 0 012 2"></path></svg>
                        <span>Filters update results instantly</span>
                    </div>
                </div>
            </div>
            <table class="min-w-full divide-y divide-gray-200">
                <thead class="bg-gray-50">
                    <tr>
                        <th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Severity</th>
                        <th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Title</th>
                        <th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Region</th>
                        <th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Resource ID</th>
                        <th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Framework</th>
                        <th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Status</th>
                    </tr>
                </thead>
                <tbody id="config-sh-findings-tbody" class="bg-white divide-y divide-gray-200">${tableRowsHtml}</tbody>
            </table>
        </div>`;

    setTimeout(() => {
        document.getElementById('status-filter').addEventListener('change', applyFilters);
        document.getElementById('severity-filter').addEventListener('change', applyFilters);
        document.getElementById('region-filter').addEventListener('change', applyFilters);
        document.getElementById('framework-filter').addEventListener('change', applyFilters);
        document.getElementById('resource-filter').addEventListener('change', applyFilters);
        document.getElementById('search-filter').addEventListener('input', applyFilters);
        
        document.getElementById('clear-filters').addEventListener('click', () => {
            document.getElementById('status-filter').value = '';
            document.getElementById('severity-filter').value = '';
            document.getElementById('region-filter').value = '';
            document.getElementById('framework-filter').value = '';
            document.getElementById('resource-filter').value = '';
            document.getElementById('search-filter').value = '';
            applyFilters();
        });
        
        applyFilters();

    }, 50);
}