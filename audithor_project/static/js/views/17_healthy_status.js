/**
 * 17_healthy_status.js
 * Contains all logic for building and rendering the Healthy Status / Executive Summary view.
 */

// --- IMPORTS ---
import { handleTabClick, log } from '../utils.js';

// Initialize global variable
if (!window.lastHealthyStatusFindings) {
    window.lastHealthyStatusFindings = [];
}

// --- MAIN VIEW FUNCTION (EXPORTED) ---
export const buildHealthyStatusView = () => {
    const container = document.getElementById('healthy-status-view');
    if (!container) return;

    container.innerHTML = `
        <header class="flex justify-between items-center mb-6">
            <div>
                <h2 class="text-2xl font-bold text-[#204071]">Healthy Status</h2>
                <p class="text-sm text-gray-500">Summary of Findings and Report Generation.</p>
            </div>
        </header>
        
        <div class="border-b border-gray-200 mb-6">
            <nav class="-mb-px flex space-x-6" id="healthy-status-tabs">
                <a href="#" data-tab="hs-findings-content" class="tab-link py-3 px-1 border-b-2 border-[#eb3496] text-[#eb3496] font-semibold text-sm">Findings</a>
                <a href="#" data-tab="hs-report-content" class="tab-link py-3 px-1 border-b-2 border-transparent text-gray-500 hover:text-gray-700 font-medium text-sm">Generate Report</a>
            </nav>
        </div>

        <div id="healthy-status-tab-content-container">
            <div id="hs-findings-content" class="healthy-status-tab-content">
                <!-- Filtros Mejorados -->
                <div class="bg-white p-4 rounded-xl border border-gray-200 mb-6">
                    <h3 class="text-sm font-semibold text-gray-800 mb-3">Filter Options</h3>
                    <div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
                        <div>
                            <label for="healthy-status-region-filter" class="block text-sm font-medium text-gray-700 mb-1">Region:</label>
                            <select id="healthy-status-region-filter" class="block w-full pl-3 pr-10 py-2 text-sm border-gray-300 focus:outline-none focus:ring-[#eb3496] focus:border-[#eb3496] rounded-md">
                                <option value="all">All Regions</option>
                            </select>
                        </div>
                        
                        <div>
                            <label for="healthy-status-severity-filter" class="block text-sm font-medium text-gray-700 mb-1">Severity:</label>
                            <select id="healthy-status-severity-filter" class="block w-full pl-3 pr-10 py-2 text-sm border-gray-300 focus:outline-none focus:ring-[#eb3496] focus:border-[#eb3496] rounded-md">
                                <option value="all">All Severities</option>
                                <option value="Crítico">Critical</option>
                                <option value="Alto">High</option>
                                <option value="Medio">Medium</option>
                                <option value="Bajo">Low</option>
                                <option value="Informativo">Info</option>
                            </select>
                        </div>
                        
                        <div>
                            <label for="healthy-status-section-filter" class="block text-sm font-medium text-gray-700 mb-1">Section:</label>
                            <select id="healthy-status-section-filter" class="block w-full pl-3 pr-10 py-2 text-sm border-gray-300 focus:outline-none focus:ring-[#eb3496] focus:border-[#eb3496] rounded-md">
                                <option value="all">All Sections</option>
                            </select>
                        </div>
                        
                        <div>
                            <label for="healthy-status-impact-filter" class="block text-sm font-medium text-gray-700 mb-1">Impact Type:</label>
                            <select id="healthy-status-impact-filter" class="block w-full pl-3 pr-10 py-2 text-sm border-gray-300 focus:outline-none focus:ring-[#eb3496] focus:border-[#eb3496] rounded-md">
                                <option value="all">All Impact Types</option>
                                <option value="compliance">Compliance Risk</option>
                                <option value="data_breach">Data Breach Risk</option>
                                <option value="operational">Operational Risk</option>
                                <option value="access_control">Access Control Risk</option>
                                <option value="monitoring">Monitoring Gap</option>
                                <option value="encryption">Encryption Issue</option>
                            </select>
                        </div>
                    </div>
                    
                    <!-- Botón de reset -->
                    <div class="mt-3 flex justify-between items-center">
                        <button id="reset-filters-btn" class="text-sm text-[#eb3496] hover:text-[#d42c86] font-medium">Reset All Filters</button>
                        <div id="findings-count-display" class="text-sm text-gray-600"></div>
                    </div>
                </div>

                <div id="healthy-status-container">
                    <div class="text-center py-16 bg-white rounded-lg">
                        <h3 class="mt-2 text-lg font-medium text-[#204071]">Waiting for analysis</h3>
                        <p class="mt-1 text-sm text-gray-500">Status findings will appear here after analyzing an account.</p>
                    </div>
                </div>
            </div>

            <div id="hs-report-content" class="healthy-status-tab-content hidden"></div>
        </div>
    `;

    const tabsNav = container.querySelector('#healthy-status-tabs');
    if (tabsNav) {
        tabsNav.addEventListener('click', handleTabClick(tabsNav, '.healthy-status-tab-content'));
    }
    
    // Setup filter event listeners
    setupFilterEventListeners();
    
    // Build the report view immediately after creating the container
    buildGeminiReportView();
};

// --- FILTER SETUP ---
const setupFilterEventListeners = () => {
    const regionFilter = document.getElementById('healthy-status-region-filter');
    const severityFilter = document.getElementById('healthy-status-severity-filter');
    const sectionFilter = document.getElementById('healthy-status-section-filter');
    const impactFilter = document.getElementById('healthy-status-impact-filter');
    const resetBtn = document.getElementById('reset-filters-btn');

    // Función de debounce para evitar múltiples llamadas rápidas
    let filterTimeout;
    const debouncedApplyFilters = () => {
        clearTimeout(filterTimeout);
        filterTimeout = setTimeout(applyFilters, 100);
    };

    // Add change listeners to all filters
    [regionFilter, severityFilter, sectionFilter, impactFilter].forEach(filter => {
        if (filter) {
            // Remover listener existente si lo hay
            filter.removeEventListener('change', debouncedApplyFilters);
            // Agregar nuevo listener
            filter.addEventListener('change', debouncedApplyFilters);
        }
    });

    // Reset filters button
    if (resetBtn) {
        resetBtn.removeEventListener('click', resetAllFilters);
        resetBtn.addEventListener('click', resetAllFilters);
    }
};

const resetAllFilters = () => {
    const filters = [
        'healthy-status-region-filter', 
        'healthy-status-severity-filter', 
        'healthy-status-section-filter', 
        'healthy-status-impact-filter'
    ];
    
    filters.forEach(filterId => {
        const filter = document.getElementById(filterId);
        if (filter) {
            filter.value = 'all';
        }
    });
    
    // Aplicar filtros inmediatamente (sin debounce para reset)
    setTimeout(applyFilters, 50);
};

const applyFilters = () => {
    const regionValue = document.getElementById('healthy-status-region-filter')?.value || 'all';
    const severityValue = document.getElementById('healthy-status-severity-filter')?.value || 'all';
    const sectionValue = document.getElementById('healthy-status-section-filter')?.value || 'all';
    const impactValue = document.getElementById('healthy-status-impact-filter')?.value || 'all';

    let filteredFindings = [...(window.lastHealthyStatusFindings || [])]; // Crear copia
    
    // Apply region filter con mejor manejo de estructuras
    if (regionValue !== 'all') {
        filteredFindings = filteredFindings.filter(finding => {
            const resources = finding.affected_resources || [];
            if (resources.length === 0) return false;
            
            return resources.some(res => {
                // Manejar tanto objetos como strings
                if (typeof res === 'object' && res !== null) {
                    const region = res.region || 'Global';
                    return region === regionValue || region === 'Global';
                } else if (typeof res === 'string') {
                    // Si es string, asumimos que es Global a menos que especifique región
                    return regionValue === 'Global';
                }
                return false;
            });
        });
    }
    
    // Apply severity filter
    if (severityValue !== 'all') {
        filteredFindings = filteredFindings.filter(finding => 
            finding.severity === severityValue
        );
    }
    
    // Apply section filter
    if (sectionValue !== 'all') {
        filteredFindings = filteredFindings.filter(finding => 
            finding.section === sectionValue
        );
    }
    
    // Apply impact type filter
    if (impactValue !== 'all') {
        filteredFindings = filteredFindings.filter(finding => 
            classifyFindingImpact(finding) === impactValue
        );
    }
    
    // Update findings count
    updateFindingsCount(filteredFindings.length, (window.lastHealthyStatusFindings || []).length);
    
    // Render filtered findings
    renderHealthyStatusFindings(filteredFindings);
};

const updateFindingsCount = (filtered, total) => {
    const countDisplay = document.getElementById('findings-count-display');
    if (countDisplay) {
        if (filtered === total) {
            countDisplay.textContent = `Showing ${total} finding${total !== 1 ? 's' : ''}`;
        } else {
            countDisplay.textContent = `Showing ${filtered} of ${total} findings`;
        }
    }
};

// --- IMPACT CLASSIFICATION ---
const classifyFindingImpact = (finding) => {
    const name = (finding.name || '').toLowerCase();
    const description = (finding.description || '').toLowerCase();
    const section = (finding.section || '').toLowerCase();
    const ruleId = (finding.rule_id || '').toLowerCase();

    // Compliance patterns
    if (ruleId.includes('pci') || name.includes('pci') || description.includes('pci') ||
        name.includes('cis') || description.includes('compliance') || 
        description.includes('standard') || description.includes('benchmark')) {
        return 'compliance';
    }

    // Data breach risk patterns
    if (name.includes('public') || name.includes('exposed') || name.includes('internet') ||
        description.includes('public access') || description.includes('publicly accessible') ||
        section.includes('internet exposure') || name.includes('unencrypted')) {
        return 'data_breach';
    }

    // Access control patterns
    if (section.includes('identity') || section.includes('access') || 
        name.includes('mfa') || name.includes('password') || name.includes('policy') ||
        name.includes('permission') || name.includes('role') || name.includes('user')) {
        return 'access_control';
    }

    // Monitoring gaps
    if (section.includes('logging') || section.includes('monitoring') || 
        name.includes('cloudtrail') || name.includes('guardduty') || name.includes('log') ||
        name.includes('disabled') || name.includes('not enabled')) {
        return 'monitoring';
    }

    // Encryption issues
    if (name.includes('encrypt') || name.includes('kms') || description.includes('encrypt') ||
        section.includes('data protection')) {
        return 'encryption';
    }

    // Default to operational risk
    return 'operational';
};

// This function is also exported because it's called from the main app.js
export const buildGeminiReportView = () => {
    const container = document.getElementById('hs-report-content');
    if (!container) return;

    const defaultPrompt = `Actúa como un consultor de ciberseguridad senior de la empresa [Nombre de tu Empresa]. El destinatario de este correo es nuestro cliente, una persona con un rol de liderazgo técnico (CTO, Tech Lead).

Tu tarea es redactar un borrador de correo electrónico claro y conciso para notificar al cliente sobre los hallazgos de seguridad identificados en su cuenta de AWS.

El correo debe tener la siguiente estructura:

**Asunto:** Resumen Ejecutivo: Hallazgos de Seguridad en su Cuenta de AWS

**Cuerpo del Correo:**

* **Saludo:** Un saludo profesional (ej: "Estimado/a [Nombre del Cliente],").
* **Introducción (1 párrafo):** Informa brevemente que se ha completado una revisión de seguridad y que a continuación se presentan los resultados clave.
* **Resumen de Hallazgos:** Presenta una lista de viñetas (bullet points). Para **cada tipo de hallazgo** identificado en el JSON que te proporciono, incluye una viñeta con:
    * El **título del hallazgo**.
    * Entre paréntesis, su **severidad**.
    * Una **breve descripción (1-2 frases)** del riesgo de negocio asociado. **No incluyas la lista detallada de recursos afectados**, solo el resumen del problema.
* **Recomendación Principal:** Basado en los hallazgos, ofrece una recomendación general y priorizada (ej: "Recomendamos centrar los esfuerzos iniciales en solucionar los hallazgos de severidad Crítica y Alta, especialmente los relacionados con la gestión de identidades y accesos.").
* **Próximos Pasos:** Propón agendar una reunión para revisar el informe técnico completo y coordinar el plan de remediación.
* **Cierre:** Un cierre cordial y profesional.

El objetivo es que el cliente entienda rápidamente qué problemas existen y cuál es su impacto, sin abrumarlo con detalles técnicos en el primer contacto. Asegúrate de que **todos los tipos de hallazgos** estén listados.

A continuación te proporciono los hallazgos en formato JSON:`;

    container.innerHTML = `
        <div class="bg-white p-6 rounded-xl shadow-sm border border-gray-100">
            <h3 class="font-bold text-lg mb-1 text-[#204071]">Generate Report with AI (Gemini)</h3>
            <p class="text-sm text-gray-500 mb-4">This tool will use the findings to generate a draft executive report.</p>
            
            <div class="mb-4">
                <label for="gemini-api-key" class="block text-sm font-medium text-gray-700 mb-1">Your Google AI Studio (Gemini) API Key</label>
                <input type="password" id="gemini-api-key" class="bg-gray-50 border border-gray-300 text-[#204071] text-sm rounded-lg focus:ring-[#eb3496] focus:border-[#eb3496] block w-full p-2.5" placeholder="Paste your API key here">
                <p class="text-xs text-gray-500 mt-1">Your key is used directly from your browser to call the Google API and is not stored anywhere.</p>
            </div>

            <div class="mb-4">
                <label for="gemini-region-filter" class="block text-sm font-medium text-gray-700 mb-1">Filter Findings by Region (Optional)</label>
                <select id="gemini-region-filter" class="bg-gray-50 border border-gray-300 text-gray-900 text-sm rounded-lg focus:ring-[#eb3496] focus:border-[#eb3496] block w-full p-2.5">
                    <option value="all">All Regions</option>
                </select>
            </div>

            <div class="mb-4">
                <label for="gemini-prompt" class="block text-sm font-medium text-gray-700 mb-1">Prompt for Gemini (Editable)</label>
                <textarea id="gemini-prompt" rows="10" class="bg-gray-50 border border-gray-300 text-[#204071] text-sm rounded-lg focus:ring-[#eb3496] focus:border-[#eb3496] block w-full p-2.5 font-mono">${defaultPrompt}</textarea>
            </div>

            <button id="generate-gemini-report-btn" class="bg-[#eb3496] text-white px-4 py-2.5 rounded-lg font-bold text-md hover:bg-[#d42c86] transition flex items-center justify-center space-x-2">
                <span id="gemini-btn-text">Generate Draft Email</span>
                <div id="gemini-spinner" class="spinner hidden"></div>
            </button>

            <div id="gemini-report-output" class="mt-6 hidden">
                 <h4 class="font-bold text-lg mb-2 text-[#204071]">Email Draft:</h4>
                 <div id="gemini-report-content" class="bg-slate-50 p-4 rounded-lg border text-sm whitespace-pre-wrap"></div>
            </div>
        </div>
    `;

    // Add event listener after the button is created
    const genButton = document.getElementById('generate-gemini-report-btn');
    if (genButton) {
        genButton.addEventListener('click', generateGeminiReport);
    }
};

// --- INTERNAL MODULE FUNCTIONS ---
export const generateGeminiReport = async () => {
    const apiKey = document.getElementById('gemini-api-key')?.value.trim();
    const userPrompt = document.getElementById('gemini-prompt')?.value.trim();
    const reportOutputContainer = document.getElementById('gemini-report-output');
    const reportContentDiv = document.getElementById('gemini-report-content');
    const runBtn = document.getElementById('generate-gemini-report-btn');
    const btnText = document.getElementById('gemini-btn-text');
    const spinner = document.getElementById('gemini-spinner');

    if (!apiKey) {
        alert('Please enter your Gemini API Key.');
        return;
    }
    
    if (!window.lastHealthyStatusFindings || window.lastHealthyStatusFindings.length === 0) {
        alert('There are no findings to generate a report. Please run an analysis first.');
        return;
    }

    if (runBtn) runBtn.disabled = true;
    if (spinner) spinner.classList.remove('hidden');
    if (btnText) btnText.textContent = 'Generating...';
    if (reportOutputContainer) reportOutputContainer.classList.add('hidden');
    if (reportContentDiv) reportContentDiv.textContent = 'Contacting the Gemini API...';
    log('Generating report with Gemini...', 'info');

    const selectedRegion = document.getElementById('gemini-region-filter')?.value || 'all';
    let findingsForReport = window.lastHealthyStatusFindings;

    if (selectedRegion !== 'all') {
        log(`Filtering findings for region: ${selectedRegion}`, 'info');
        findingsForReport = window.lastHealthyStatusFindings.map(finding => {
            const affectedInRegion = finding.affected_resources.filter(res => 
                res.region === selectedRegion || res.region === 'Global'
            );
            if (affectedInRegion.length > 0) {
                return { ...finding, affected_resources: affectedInRegion };
            }
            return null;
        }).filter(Boolean);
    }

    const findingsJson = JSON.stringify(findingsForReport, null, 2);
    const fullPrompt = `${userPrompt}\n\n${findingsJson}`;
    const API_ENDPOINT = `https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-flash-latest:generateContent?key=${apiKey}`;

    try {
        const response = await fetch(API_ENDPOINT, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                contents: [{ parts: [{ text: fullPrompt }] }]
            })
        });

        if (!response.ok) {
            const errorData = await response.json();
            throw new Error(`Gemini API Error: ${errorData.error?.message || 'Unknown API error'}`);
        }

        const data = await response.json();
        const reportText = data.candidates?.[0]?.content?.parts?.[0]?.text || 'No response generated';
        
        if (reportContentDiv) reportContentDiv.textContent = reportText;
        if (reportOutputContainer) reportOutputContainer.classList.remove('hidden');
        log('Report generated by Gemini successfully.', 'success');

    } catch (error) {
        const errorMsg = `Error generating report:\n${error.message}`;
        if (reportContentDiv) reportContentDiv.textContent = errorMsg;
        if (reportOutputContainer) reportOutputContainer.classList.remove('hidden');
        log(`Error in Gemini API call: ${error.message}`, 'error');
    } finally {
        if (runBtn) runBtn.disabled = false;
        if (spinner) spinner.classList.add('hidden');
        if (btnText) btnText.textContent = 'Generate Draft Email';
    }
};

// Sample rule checking function - you'll need to implement the actual rules
export const check_healthy_status_rules = (auditData) => {
    const findings = [];
    
    try {
        // Example: Check for MFA rule
        const users = auditData.iam?.results?.users || [];
        const noMfaUsers = users.filter(user => 
            !user.MFADevices || user.MFADevices.length === 0
        ).map(user => user.UserName || 'Unknown user');
        
        if (noMfaUsers.length > 0) {
            findings.push({
                rule_id: "IAM_001",
                section: "Identity & Access",
                name: "User without MFA enabled",
                severity: "Alto",
                description: "IAM users without Multi-Factor Authentication (MFA) enabled pose a significant security risk.",
                remediation: "Enable MFA for all IAM users, especially those with console access.",
                affected_resources: noMfaUsers.map(name => ({ resource: name, region: 'Global' }))
            });
        }

        // Example: Check for GuardDuty rule
        const guarddutyStatus = auditData.guardduty?.results?.status || [];
        const disabledGuardDuty = guarddutyStatus.filter(status => 
            status.Status !== "Enabled"
        ).map(status => status.Region);
        
        if (disabledGuardDuty.length > 0) {
            findings.push({
                rule_id: "GUARDDUTY_001",
                section: "Security Services",
                name: "GuardDuty not enabled in some regions",
                severity: "Medio",
                description: "AWS GuardDuty provides threat detection but is not enabled in all regions.",
                remediation: "Enable GuardDuty in all active AWS regions for comprehensive threat detection.",
                affected_resources: disabledGuardDuty.map(region => ({ resource: 'GuardDuty Service', region }))
            });
        }

        // Add more rules here as needed...

    } catch (error) {
        console.error('Error in rule checking:', error);
        log(`Error checking rules: ${error.message}`, 'error');
    }

    return findings;
};

export const renderHealthyStatusFindings = (findings) => {
    const container = document.getElementById('healthy-status-container');
    if (!container) return;

    if (!findings || findings.length === 0) {
        container.innerHTML = `
            <div class="bg-white p-6 rounded-xl shadow-sm border border-gray-100">
                <div class="flex items-center justify-center text-green-600">
                    <svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" fill="currentColor" class="bi bi-patch-check-fill mr-3" viewBox="0 0 16 16"><path d="M10.067.87a2.89 2.89 0 0 0-4.134 0l-.622.638-.89-.011a2.89 2.89 0 0 0-2.924 2.924l.01.89-.636.622a2.89 2.89 0 0 0 0 4.134l.637.622-.011.89a2.89 2.89 0 0 0 2.924 2.924l.89-.01.622.636a2.89 2.89 0 0 0 4.134 0l.622-.637.89.01a2.89 2.89 0 0 0 2.924-2.924l-.01-.89.636-.622a2.89 2.89 0 0 0 0-4.134l-.637-.622.011-.89a2.89 2.89 0 0 0-2.924-2.924l-.89.01zm.287 5.984-3 3a.5.5 0 0 1-.708 0l-1.5-1.5a.5.5 0 1 1 .708-.708L7 8.793l2.646-2.647a.5.5 0 0 1 .708.708"/></svg>
                    <p class="text-center font-semibold text-lg">¡Congratulations! No findings were found for the selected criteria.</p>
                </div>
            </div>
        `;
        return;
    }

    // Sort findings by severity
    const severityOrder = { 'Crítico': 1, 'Alto': 2, 'Medio': 3, 'Bajo': 4, 'Informativo': 5 };
    const sortedFindings = [...findings].sort((a, b) => (severityOrder[a.severity] || 99) - (severityOrder[b.severity] || 99));

    container.innerHTML = '';
    
    sortedFindings.forEach(finding => {
        let borderColor = 'border-gray-500';
        let severityBadgeColor = 'bg-gray-100 text-gray-800';
        
        if (finding.severity === 'Crítico') {
            borderColor = 'border-red-600';
            severityBadgeColor = 'bg-red-100 text-red-800';
        }
        if (finding.severity === 'Alto') {
            borderColor = 'border-red-500';
            severityBadgeColor = 'bg-red-100 text-red-800';
        }
        if (finding.severity === 'Medio') {
            borderColor = 'border-yellow-500';
            severityBadgeColor = 'bg-yellow-100 text-yellow-800';
        }
        if (finding.severity === 'Bajo') {
            borderColor = 'border-blue-500';
            severityBadgeColor = 'bg-blue-100 text-blue-800';
        }
        if (finding.severity === 'Informativo') {
            borderColor = 'border-gray-400';
            severityBadgeColor = 'bg-gray-100 text-gray-600';
        }

        // Create display format for affected resources
        const affectedResourcesWithDisplay = (finding.affected_resources || []).map(res => {
            if (typeof res === 'object' && res.resource && res.region) {
                return {
                    ...res,
                    display: `${res.resource} (${res.region})`
                };
            } else if (typeof res === 'string') {
                return {
                    resource: res,
                    region: 'Global',
                    display: `${res} (Global)`
                };
            } else {
                return {
                    resource: 'Unknown',
                    region: 'Global',
                    display: 'Unknown (Global)'
                };
            }
        });

        const affectedResourcesHtml = affectedResourcesWithDisplay.map(res => 
            `<li>${res.display}</li>`
        ).join('');
        
        const resourcesCount = affectedResourcesWithDisplay.length;
        const impactType = classifyFindingImpact(finding);
        const impactLabel = {
            'compliance': 'Compliance Risk',
            'data_breach': 'Data Breach Risk', 
            'operational': 'Operational Risk',
            'access_control': 'Access Control Risk',
            'monitoring': 'Monitoring Gap',
            'encryption': 'Encryption Issue'
        }[impactType] || 'Operational Risk';

        const card = `
            <div class="bg-white p-4 rounded-xl mb-4 border-l-4 ${borderColor} shadow-sm">
                <div class="flex flex-wrap items-center justify-between mb-2">
                    <h3 class="text-xl font-bold text-[#204071] flex-grow">${finding.name || 'Unknown finding'}</h3>
                    <div class="flex space-x-2 mt-1 sm:mt-0">
                        <span class="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium ${severityBadgeColor}">${finding.severity || 'UNKNOWN'}</span>
                        <span class="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium bg-blue-50 text-blue-700">${impactLabel}</span>
                    </div>
                </div>
                <p class="text-gray-600 mt-2 text-sm">${finding.description || 'No description available'}</p>
                <div class="mt-4">
                    <details class="group">
                        <summary class="font-semibold text-gray-800 text-sm cursor-pointer list-none flex items-center">
                            <svg class="w-4 h-4 mr-2 group-open:rotate-90 transition-transform" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 5l7 7-7 7"></path></svg>
                            Affected Resources (${resourcesCount}):
                        </summary>
                        <ul class="list-disc list-inside text-sm text-gray-700 bg-gray-50 p-2 rounded-md mt-2 font-mono ml-6">
                            ${affectedResourcesHtml}
                        </ul>
                    </details>
                </div>
                <div class="mt-4">
                    <h4 class="font-semibold text-gray-800 text-sm">Recommended Solution:</h4>
                    <p class="text-gray-600 text-sm">${finding.remediation || 'No remediation information available'}</p>
                </div>
            </div>
        `;
        container.innerHTML += card;
    });
};

export const populateHealthyStatusFilter = (findings) => {
    const regionSelect = document.getElementById('healthy-status-region-filter');
    const sectionSelect = document.getElementById('healthy-status-section-filter');
    const geminiRegionSelect = document.getElementById('gemini-region-filter'); // También actualizar este
    
    if (!regionSelect || !sectionSelect) return;

    // Populate regions con mejor manejo
    const regions = new Set();
    
    (findings || []).forEach(finding => {
        (finding.affected_resources || []).forEach(res => {
            if (typeof res === 'object' && res !== null && res.region) {
                regions.add(res.region);
            } else {
                // Si no tiene región especificada, agregar Global
                regions.add('Global');
            }
        });
    });

    // Limpiar y repoblar regiones
    regionSelect.innerHTML = '<option value="all">All Regions</option>';
    if (geminiRegionSelect) {
        geminiRegionSelect.innerHTML = '<option value="all">All Regions</option>';
    }
    
    const sortedRegions = Array.from(regions).sort();
    sortedRegions.forEach(region => {
        const option = document.createElement('option');
        option.value = region;
        option.textContent = region;
        regionSelect.appendChild(option);
        
        // También actualizar el select de Gemini
        if (geminiRegionSelect) {
            const geminiOption = document.createElement('option');
            geminiOption.value = region;
            geminiOption.textContent = region;
            geminiRegionSelect.appendChild(geminiOption);
        }
    });

    // Populate sections
    const sections = new Set();
    
    (findings || []).forEach(finding => {
        if (finding.section) {
            sections.add(finding.section);
        }
    });

    sectionSelect.innerHTML = '<option value="all">All Sections</option>';
    const sortedSections = Array.from(sections).sort();
    sortedSections.forEach(section => {
        const option = document.createElement('option');
        option.value = section;
        option.textContent = section;
        sectionSelect.appendChild(option);
    });

    // Actualizar findings count inicial
    if (findings && findings.length > 0) {
        updateFindingsCount(findings.length, findings.length);
    }
};

// Nueva función para inicializar los filtros después de cargar datos
export const initializeFiltersAfterDataLoad = (findings) => {
    // Guardar los findings
    window.lastHealthyStatusFindings = findings || [];
    
    // Poblar los filtros
    populateHealthyStatusFilter(findings);
    
    // Mostrar todos los findings inicialmente
    renderHealthyStatusFindings(findings);
    
    // Asegurar que los event listeners están configurados
    setupFilterEventListeners();
};