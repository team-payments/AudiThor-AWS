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

    // CORRECCIÓN: Validar que findings es un array
    if (!Array.isArray(findings)) {
        console.warn('findings is not an array:', findings);
        findings = [];
    }

    // NUEVO: Filtrar findings de Inspector
    const filteredFindings = findings.filter(f => {
        // Excluir findings de Inspector basándose en diferentes criterios
        const isInspectorCVE = f.Title && f.Title.includes('CVE-');
        const isInspectorTitle = f.Title && (f.Title.includes('Inspector') || f.Title.includes('Network reachability'));
        const isInspectorProduct = f.ProductArn && f.ProductArn.includes('inspector');
        const isInspectorGenerator = f.GeneratorId && f.GeneratorId.includes('inspector');
        
        // Retornar false (excluir) si es de Inspector
        return !(isInspectorCVE || isInspectorTitle || isInspectorProduct || isInspectorGenerator);
    });

    if (filteredFindings.length === 0) {
        container.innerHTML = `<div class="bg-white p-6 rounded-xl border border-gray-100"><p class="text-center text-gray-500">No Security Hub compliance findings were found (Inspector findings excluded).</p></div>`;
        return;
    }

    // Función mejorada para detectar tipos de recurso
    const getResourceType = (finding) => {
        // Primero intentar usar el campo Type si existe
        const resourceType = finding.Resources?.[0]?.Type;
        if (resourceType) {
            // Mapear tipos AWS estándar a nombres legibles
            const typeMapping = {
                'AwsEc2Instance': 'EC2 Instance',
                'AwsS3Bucket': 'S3 Bucket',
                'AwsEc2SecurityGroup': 'Security Group',
                'AwsIamRole': 'IAM Role',
                'AwsIamUser': 'IAM User',
                'AwsIamPolicy': 'IAM Policy',
                'AwsLambdaFunction': 'Lambda Function',
                'AwsEc2Vpc': 'VPC',
                'AwsEc2Subnet': 'Subnet',
                'AwsElbv2LoadBalancer': 'Load Balancer',
                'AwsElbLoadBalancer': 'Classic Load Balancer',
                'AwsRdsDbInstance': 'RDS Instance',
                'AwsRdsDbCluster': 'RDS Cluster',
                'AwsCloudFrontDistribution': 'CloudFront',
                'AwsApiGatewayRestApi': 'API Gateway',
                'AwsKmsKey': 'KMS Key',
                'AwsSecretsManagerSecret': 'Secrets Manager',
                'AwsEcsCluster': 'ECS Cluster',
                'AwsEksCluster': 'EKS Cluster',
                'AwsSnsSubscription': 'SNS',
                'AwsSqsQueue': 'SQS Queue',
                'AwsCloudTrailTrail': 'CloudTrail',
                'AwsCloudWatchAlarm': 'CloudWatch',
                'AwsAutoScalingGroup': 'Auto Scaling',
                'AwsConfigConfigurationRecorder': 'Config',
                'AwsGuardDutyDetector': 'GuardDuty',
                'AwsWafWebAcl': 'WAF',
                'AwsCodeBuildProject': 'CodeBuild',
                'AwsCodePipelinePipeline': 'CodePipeline',
                'AwsRedshiftCluster': 'Redshift',
                'AwsElasticSearchDomain': 'OpenSearch',
                'AwsBackupBackupVault': 'Backup Vault',
                'AwsEcrRepository': 'ECR Repository'
            };
            
            const mappedType = typeMapping[resourceType];
            if (mappedType) return mappedType;
            
            // Si no está en el mapeo, extraer nombre genérico
            const genericType = resourceType.replace(/^Aws/, '').replace(/([A-Z])/g, ' $1').trim();
            return genericType;
        }
        
        // Fallback: analizar Resource ID con patrones mejorados
        const resourceId = finding.Resources?.[0]?.Id || '';
        if (resourceId.includes(':instance/')) return 'EC2 Instance';
        if (resourceId.includes(':bucket/')) return 'S3 Bucket';
        if (resourceId.includes(':security-group/')) return 'Security Group';
        if (resourceId.includes(':role/')) return 'IAM Role';
        if (resourceId.includes(':user/')) return 'IAM User';
        if (resourceId.includes(':policy/')) return 'IAM Policy';
        if (resourceId.includes(':function/')) return 'Lambda Function';
        if (resourceId.includes(':vpc/')) return 'VPC';
        if (resourceId.includes(':subnet/')) return 'Subnet';
        if (resourceId.includes(':loadbalancer/')) return 'Load Balancer';
        if (resourceId.includes(':db:')) return 'RDS';
        if (resourceId.includes(':distribution/')) return 'CloudFront';
        if (resourceId.includes(':restapi/')) return 'API Gateway';
        if (resourceId.includes(':key/')) return 'KMS Key';
        if (resourceId.includes(':secret:')) return 'Secrets Manager';
        if (resourceId.includes(':cluster/')) return 'Cluster';
        if (resourceId.includes(':trail/')) return 'CloudTrail';
        if (resourceId.includes(':alarm/')) return 'CloudWatch';
        if (resourceId.includes(':topic/')) return 'SNS';
        if (resourceId.includes(':queue/')) return 'SQS';
        if (resourceId.includes(':repository/')) return 'ECR Repository';
        if (resourceId.includes('AwsAccount')) return 'Account';
        
        return 'Other';
    };

    // Obtener valores únicos para los filtros
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
                if (standardsArn.includes('service-managed')) return 'Service Managed';
                const parts = standardsArn.split('/standard/');
                if (parts.length > 1) {
                    return parts[1].split('/')[0].replace(/-/g, ' ').toUpperCase();
                }
            }
            return null;
        }).filter(Boolean))],
        resourceTypes: [...new Set(filteredFindings.map(f => getResourceType(f)).filter(Boolean))]
    };

    // Ordenar los arrays de valores únicos
    uniqueValues.severities.sort((a, b) => {
        const order = { "CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFORMATIONAL": 4 };
        return (order[a] || 99) - (order[b] || 99);
    });
    uniqueValues.regions.sort();
    uniqueValues.frameworks.sort();
    uniqueValues.resourceTypes.sort();

    // Ordenar hallazgos por severidad
    const severityOrder = { "CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFORMATIONAL": 4 };
    filteredFindings.sort((a, b) => {
        const severityA = severityOrder[a.Severity?.Label] ?? 99;
        const severityB = severityOrder[b.Severity?.Label] ?? 99;
        return severityA - severityB;
    });

    // Función para aplicar filtros
    const applyFilters = () => {
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

            // Filtro por severidad
            if (severityFilter && finding.Severity?.Label !== severityFilter) {
                shouldShow = false;
            }

            // Filtro por región
            if (regionFilter && finding.Region !== regionFilter) {
                shouldShow = false;
            }

            // Filtro por framework
            if (frameworkFilter) {
                let framework = 'N/A';
                if (finding.ProductFields && finding.ProductFields['StandardsArn']) {
                    const standardsArn = finding.ProductFields['StandardsArn'];
                    if (standardsArn.includes('pci-dss')) framework = 'PCI DSS';
                    else if (standardsArn.includes('aws-foundational-security-best-practices')) framework = 'AWS FSBP';
                    else if (standardsArn.includes('cis')) framework = 'CIS';
                    else if (standardsArn.includes('nist')) framework = 'NIST';
                    else if (standardsArn.includes('service-managed')) framework = 'Service Managed';
                    else {
                        const parts = standardsArn.split('/standard/');
                        if (parts.length > 1) {
                            framework = parts[1].split('/')[0].replace(/-/g, ' ').toUpperCase();
                        }
                    }
                }
                if (framework !== frameworkFilter) {
                    shouldShow = false;
                }
            }

            // Filtro por tipo de recurso (MEJORADO)
            if (resourceFilter) {
                const resourceType = getResourceType(finding);
                if (resourceType !== resourceFilter) {
                    shouldShow = false;
                }
            }

            // Filtro por búsqueda de texto
            if (searchFilter) {
                const title = (finding.Title || '').toLowerCase();
                const resourceId = (finding.Resources?.[0]?.Id || '').toLowerCase();
                if (!title.includes(searchFilter) && !resourceId.includes(searchFilter)) {
                    shouldShow = false;
                }
            }

            if (shouldShow) {
                row.style.display = '';
                visibleCount++;
            } else {
                row.style.display = 'none';
            }
        });

        // Actualizar contador
        document.getElementById('visible-findings-count').textContent = `Showing ${visibleCount} of ${filteredFindings.length} findings`;
    };

    // Crear HTML de la tabla con filtros
    let tableRowsHtml = filteredFindings.map(f => {
        const severity = f.Severity?.Label || 'N/A';
        const title = f.Title || 'No Title';
        const region = f.Region || 'Global';
        const resourceId = f.Resources?.[0]?.Id || 'N/A';
        const status = f.RecordState || 'N/A';
        
        // Extraer el framework/standard
        let framework = 'N/A';
        if (f.ProductFields && f.ProductFields['StandardsArn']) {
            const standardsArn = f.ProductFields['StandardsArn'];
            if (standardsArn.includes('pci-dss')) {
                framework = 'PCI DSS';
            } else if (standardsArn.includes('aws-foundational-security-best-practices')) {
                framework = 'AWS FSBP';
            } else if (standardsArn.includes('cis')) {
                framework = 'CIS';
            } else if (standardsArn.includes('nist')) {
                framework = 'NIST';
            } else if (standardsArn.includes('service-managed')) {
                framework = 'Service Managed';
            } else {
                const parts = standardsArn.split('/standard/');
                if (parts.length > 1) {
                    const standardName = parts[1].split('/')[0];
                    framework = standardName.replace(/-/g, ' ').toUpperCase();
                    if (framework.length > 20) {
                        framework = framework.substring(0, 17) + '...';
                    }
                }
            }
        }
        
        const badgeColor = {
            'CRITICAL': 'bg-red-100 text-red-800',
            'HIGH': 'bg-orange-100 text-orange-800',
            'MEDIUM': 'bg-yellow-100 text-yellow-800',
            'LOW': 'bg-blue-100 text-blue-800',
            'INFORMATIONAL': 'bg-gray-100 text-gray-800'
        }[severity] || 'bg-gray-100 text-gray-800';

        return `
            <tr class="finding-row hover:bg-gray-50">
                <td class="px-4 py-3 align-top"><span class="px-2.5 py-1 text-xs font-bold rounded-full ${badgeColor}">${severity}</span></td>
                <td class="px-4 py-3 align-top text-sm font-medium text-gray-800">${title}</td>
                <td class="px-4 py-3 align-top text-sm text-gray-600">${region}</td>
                <td class="px-4 py-3 align-top text-sm text-gray-600 break-all">${resourceId}</td>
                <td class="px-4 py-3 align-top text-sm text-gray-600">
                    <span class="px-2 py-1 text-xs font-medium rounded-md bg-blue-50 text-blue-700">${framework}</span>
                </td>
                <td class="px-4 py-3 align-top text-sm text-gray-600">${status}</td>
            </tr>`;
    }).join('');

    container.innerHTML = `
        <div class="bg-white p-6 rounded-xl shadow-sm border border-gray-100 overflow-x-auto">
            <!-- Filtros -->
            <div class="mb-6 p-4 bg-gray-50 rounded-lg">
                <div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 xl:grid-cols-6 gap-4">
                    <div>
                        <label class="block text-xs font-medium text-gray-700 mb-1">Severity</label>
                        <select id="severity-filter" class="w-full text-sm border border-gray-300 rounded-md px-2 py-1">
                            <option value="">All Severities</option>
                            ${uniqueValues.severities.map(s => `<option value="${s}">${s}</option>`).join('')}
                        </select>
                    </div>
                    <div>
                        <label class="block text-xs font-medium text-gray-700 mb-1">Region</label>
                        <select id="region-filter" class="w-full text-sm border border-gray-300 rounded-md px-2 py-1">
                            <option value="">All Regions</option>
                            ${uniqueValues.regions.map(r => `<option value="${r}">${r}</option>`).join('')}
                        </select>
                    </div>
                    <div>
                        <label class="block text-xs font-medium text-gray-700 mb-1">Framework</label>
                        <select id="framework-filter" class="w-full text-sm border border-gray-300 rounded-md px-2 py-1">
                            <option value="">All Frameworks</option>
                            ${uniqueValues.frameworks.map(f => `<option value="${f}">${f}</option>`).join('')}
                        </select>
                    </div>
                    <div>
                        <label class="block text-xs font-medium text-gray-700 mb-1">Resource Type</label>
                        <select id="resource-filter" class="w-full text-sm border border-gray-300 rounded-md px-2 py-1">
                            <option value="">All Resources</option>
                            ${uniqueValues.resourceTypes.map(r => `<option value="${r}">${r}</option>`).join('')}
                        </select>
                    </div>
                    <div>
                        <label class="block text-xs font-medium text-gray-700 mb-1">Search</label>
                        <input type="text" id="search-filter" placeholder="Search title or resource..." 
                               class="w-full text-sm border border-gray-300 rounded-md px-2 py-1">
                    </div>
                    <div class="flex items-end">
                        <button id="clear-filters" class="px-3 py-1 text-sm bg-gray-200 text-gray-700 rounded-md hover:bg-gray-300">
                            Clear Filters
                        </button>
                    </div>
                </div>
            </div>
            
            <!-- Contador de resultados -->
            <div class="mb-4 text-sm text-gray-600">
                <span id="visible-findings-count">Showing ${filteredFindings.length} of ${filteredFindings.length} findings</span>
                <span class="text-gray-400">(${findings.length - filteredFindings.length} Inspector findings filtered out)</span>
            </div>
            
            <!-- Tabla -->
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
            <div id="config-sh-findings-pagination" class="mt-4"></div>
        </div>`;

    // Configurar event listeners para los filtros
    setTimeout(() => {
        document.getElementById('severity-filter').addEventListener('change', applyFilters);
        document.getElementById('region-filter').addEventListener('change', applyFilters);
        document.getElementById('framework-filter').addEventListener('change', applyFilters);
        document.getElementById('resource-filter').addEventListener('change', applyFilters);
        document.getElementById('search-filter').addEventListener('input', applyFilters);
        
        document.getElementById('clear-filters').addEventListener('click', () => {
            document.getElementById('severity-filter').value = '';
            document.getElementById('region-filter').value = '';
            document.getElementById('framework-filter').value = '';
            document.getElementById('resource-filter').value = '';
            document.getElementById('search-filter').value = '';
            applyFilters();
        });

        // Configurar paginación
        const rows = document.querySelectorAll('#config-sh-findings-tbody .finding-row');
        const paginationContainer = document.getElementById('config-sh-findings-pagination');
        
        if (rows.length > 0 && paginationContainer) {
            setupPaginationNew({
                rowsSelector: '#config-sh-findings-tbody .finding-row',
                paginationContainerSelector: '#config-sh-findings-pagination',
                rowsPerPage: 15
            });
        }
    }, 50);
}