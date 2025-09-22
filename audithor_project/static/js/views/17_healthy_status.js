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
                <a href="#" data-tab="hs-inventory-content" class="tab-link py-3 px-1 border-b-2 border-transparent text-gray-500 hover:text-gray-700 font-medium text-sm">Scoped Inventory</a>
                <a href="#" data-tab="hs-notes-content" class="tab-link py-3 px-1 border-b-2 border-transparent text-gray-500 hover:text-gray-700 font-medium text-sm">Auditor's Notes</a>
            </nav>
        </div>

        <div id="healthy-status-tab-content-container">
            <div id="hs-findings-content" class="healthy-status-tab-content">
                <div class="bg-gradient-to-r from-white to-gray-50 p-6 rounded-2xl border border-gray-200 shadow-sm mb-6">
                    <div class="flex items-center justify-between mb-4">
                        <div class="flex items-center space-x-2">
                            <svg class="w-5 h-5 text-[#eb3496]" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M3 4a1 1 0 011-1h16a1 1 0 011 1v2.586a1 1 0 01-.293.707l-6.414 6.414a1 1 0 00-.293.707V17l-4 4v-6.586a1 1 0 00-.293.707L3.293 7.707A1 1 0 013 7V4z"></path>
                            </svg>
                            <h3 class="text-lg font-bold text-gray-800">Filter Options</h3>
                        </div>
                        <div id="findings-count-display" class="bg-[#eb3496] text-white px-3 py-1 rounded-full text-sm font-semibold"></div>
                    </div>
                    
                    <div class="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-4 gap-4 mb-4">
                        <div class="group">
                            <label for="healthy-status-region-filter" class="flex items-center text-sm font-semibold text-gray-700 mb-2">
                                <svg xmlns="http://www.w3.org/2000/svg" fill="currentColor" class="w-4 h-4 mr-1 text-blue-500" viewBox="0 0 16 16">
                                    <path d="M12.166 8.94c-.524 1.062-1.234 2.12-1.96 3.07A32 32 0 0 1 8 14.58a32 32 0 0 1-2.206-2.57c-.726-.95-1.436-2.008-1.96-3.07C3.304 7.867 3 6.862 3 6a5 5 0 0 1 10 0c0 .862-.305 1.867-.834 2.94M8 16s6-5.686 6-10A6 6 0 0 0 2 6c0 4.314 6 10 6 10"/>
                                    <path d="M8 8a2 2 0 1 1 0-4 2 2 0 0 1 0 4m0 1a3 3 0 1 0 0-6 3 3 0 0 0 0 6"/>
                                </svg>
                                Region
                            </label>
                            <select id="healthy-status-region-filter" class="w-full px-4 py-2.5 text-sm border-2 border-gray-200 rounded-xl focus:outline-none focus:ring-2 focus:ring-[#eb3496] focus:border-[#eb3496] transition-all duration-200 bg-white hover:border-gray-300 group-hover:border-blue-300">
                                <option value="all">All Regions</option>
                            </select>
                        </div>
                        
                        <div class="group">
                            <label for="healthy-status-severity-filter" class="flex items-center text-sm font-semibold text-gray-700 mb-2">
                                <svg xmlns="http://www.w3.org/2000/svg" fill="currentColor" class="w-4 h-4 mr-1 text-red-500" viewBox="0 0 16 16">
                                    <path d="M7.938 2.016A.13.13 0 0 1 8.002 2a.13.13 0 0 1 .063.016.15.15 0 0 1 .054.057l6.857 11.667c.036.06.035.124.002.183a.2.2 0 0 1-.054.06.1.1 0 0 1-.066.017H1.146a.1.1 0 0 1-.066-.017.2.2 0 0 1-.054-.06.18.18 0 0 1 .002-.183L7.884 2.073a.15.15 0 0 1 .054-.057m1.044-.45a1.13 1.13 0 0 0-1.96 0L.165 13.233c-.457.778.091 1.767.98 1.767h13.713c.889 0 1.438-.99.98-1.767z"/>
                                    <path d="M7.002 12a1 1 0 1 1 2 0 1 1 0 0 1-2 0M7.1 5.995a.905.905 0 1 1 1.8 0l-.35 3.507a.552.552 0 0 1-1.1 0z"/>
                                </svg>
                                Severity
                            </label>
                            <select id="healthy-status-severity-filter" class="severity-select w-full px-4 py-2.5 text-sm border-2 border-gray-200 rounded-xl focus:outline-none focus:ring-2 focus:ring-[#eb3496] focus:border-[#eb3496] transition-all duration-200 bg-white hover:border-gray-300 group-hover:border-red-300">
                                <option value="all">All Severities</option>
                                <option value="Crítico" data-color="critical">Critical</option>
                                <option value="Alto" data-color="high">High</option>
                                <option value="Medio" data-color="medium">Medium</option>
                                <option value="Bajo" data-color="low">Low</option>
                                <option value="Informativo" data-color="info">Info</option>
                            </select>
                        </div>
                        
                        <div class="group">
                            <label for="healthy-status-section-filter" class="flex items-center text-sm font-semibold text-gray-700 mb-2">
                                <svg xmlns="http://www.w3.org/2000/svg" fill="currentColor" class="w-4 h-4 mr-1 text-green-500" viewBox="0 0 16 16">
                                    <path d="M8.186 1.113a.5.5 0 0 0-.372 0L1.846 3.5 8 5.961 14.154 3.5zM15 4.239l-6.5 2.6v7.922l6.5-2.6V4.24zM7.5 14.762V6.838L1 4.239v7.923zM7.443.184a1.5 1.5 0 0 1 1.114 0l7.129 2.852A.5.5 0 0 1 16 3.5v8.662a1 1 0 0 1-.629.928l-7.185 2.874a.5.5 0 0 1-.372 0L.63 13.09a1 1 0 0 1-.63-.928V3.5a.5.5 0 0 1 .314-.464z"/>
                                </svg>
                                Section
                            </label>
                            <select id="healthy-status-section-filter" class="w-full px-4 py-2.5 text-sm border-2 border-gray-200 rounded-xl focus:outline-none focus:ring-2 focus:ring-[#eb3496] focus:border-[#eb3496] transition-all duration-200 bg-white hover:border-gray-300 group-hover:border-green-300">
                                <option value="all">All Sections</option>
                            </select>
                        </div>
                        
                        <div class="group">
                            <label for="healthy-status-impact-filter" class="flex items-center text-sm font-semibold text-gray-700 mb-2">
                                <svg xmlns="http://www.w3.org/2000/svg" fill="currentColor" class="w-4 h-4 mr-1 text-purple-500" viewBox="0 0 16 16">
                                    <path d="M8 16c3.314 0 6-2 6-5.5 0-1.5-.5-4-2.5-6 .25 1.5-1.25 2-1.25 2C11 4 9 .5 6 0c.357 2 .5 4-2 6-1.25 1-2 2.729-2 4.5C2 14 4.686 16 8 16m0-1c-1.657 0-3-1-3-2.75 0-.75.25-2 1.25-3C6.125 10 7 10.5 7 10.5c-.375-1.25.5-3.25 2-3.5-.179 1-.25 2 1 3 .625.5 1 1.364 1 2.25C11 14 9.657 15 8 15"/>
                                </svg>
                                Impact Type
                            </label>
                            <select id="healthy-status-impact-filter" class="impact-select w-full px-4 py-2.5 text-sm border-2 border-gray-200 rounded-xl focus:outline-none focus:ring-2 focus:ring-[#eb3496] focus:border-[#eb3496] transition-all duration-200 bg-white hover:border-gray-300 group-hover:border-purple-300">
                                <option value="all">All Impact Types</option>
                                <option value="compliance" data-color="compliance">Compliance Risk</option>
                                <option value="data_breach" data-color="data-breach">Data Breach Risk</option>
                                <option value="operational" data-color="operational">Operational Risk</option>
                                <option value="access_control" data-color="access-control">Access Control Risk</option>
                                <option value="monitoring" data-color="monitoring">Monitoring Gap</option>
                                <option value="encryption" data-color="encryption">Encryption Issue</option>
                            </select>
                        </div>
                    </div>
                    
                    <div id="active-filters-display" class="hidden mb-4">
                        <div class="flex flex-wrap items-center gap-2">
                            <span class="text-sm font-medium text-gray-600">Active filters:</span>
                            <div id="active-filters-container" class="flex flex-wrap gap-2"></div>
                        </div>
                    </div>
                    
                    <div class="flex justify-between items-center pt-4 border-t border-gray-200">
                        <button id="reset-filters-btn" class="inline-flex items-center px-4 py-2 text-sm font-medium text-[#eb3496] bg-pink-50 border border-pink-200 rounded-xl hover:bg-pink-100 hover:border-[#eb3496] transition-all duration-200 group">
                            <svg class="w-4 h-4 mr-2 group-hover:rotate-180 transition-transform duration-300" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15"></path>
                            </svg>
                            Reset All Filters
                        </button>
                        
                        <div class="flex items-center space-x-2 text-sm text-gray-600">
                            <svg class="w-4 h-4 text-gray-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 5H7a2 2 0 00-2 2v12a2 2 0 002 2h10a2 2 0 002-2V7a2 2 0 00-2-2h-2M9 5a2 2 0 002 2h2a2 2 0 002-2M9 5a2 2 0 012-2h2a2 2 0 012 2"></path>
                            </svg>
                            <span>Active filters will update results instantly</span>
                        </div>
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
            <div id="hs-inventory-content" class="healthy-status-tab-content hidden"></div>
            <div id="hs-notes-content" class="healthy-status-tab-content hidden"></div>
        </div>
        
        <style>
        .severity-pill-critical { background-color: #fee2e2; color: #991b1b; border: 1px solid #fca5a5; }
        .severity-pill-high { background-color: #fef3c7; color: #92400e; border: 1px solid #fbbf24; }
        .severity-pill-medium { background-color: #fef3c7; color: #d97706; border: 1px solid #f59e0b; }
        .severity-pill-low { background-color: #dbeafe; color: #1e40af; border: 1px solid #60a5fa; }
        .severity-pill-info { background-color: #f3f4f6; color: #374151; border: 1px solid #d1d5db; }

        .impact-pill-compliance { background-color: #f0f9ff; color: #0c4a6e; border: 1px solid #7dd3fc; }
        .impact-pill-data-breach { background-color: #fef2f2; color: #7f1d1d; border: 1px solid #fca5a5; }
        .impact-pill-operational { background-color: #f0fdf4; color: #14532d; border: 1px solid #86efac; }
        .impact-pill-access-control { background-color: #faf5ff; color: #581c87; border: 1px solid #c084fc; }
        .impact-pill-monitoring { background-color: #fff7ed; color: #9a3412; border: 1px solid #fdba74; }
        .impact-pill-encryption { background-color: #ecfdf5; color: #065f46; border: 1px solid #6ee7b7; }

        .filter-pill {
            display: inline-flex;
            align-items: center;
            padding: 0.25rem 0.75rem;
            border-radius: 9999px;
            font-size: 0.75rem;
            font-weight: 500;
            gap: 0.375rem;
        }
        </style>
    `;

    const tabsNav = container.querySelector('#healthy-status-tabs');
    if (tabsNav) {
        tabsNav.addEventListener('click', handleTabClick(tabsNav, '.healthy-status-tab-content'));
    }
    
    setupFilterEventListeners();
    buildGeminiReportView();
    buildScopedInventoryView();
};

// --- FILTER SETUP ---
const setupFilterEventListeners = () => {
    const regionFilter = document.getElementById('healthy-status-region-filter');
    const severityFilter = document.getElementById('healthy-status-severity-filter');
    const sectionFilter = document.getElementById('healthy-status-section-filter');
    const impactFilter = document.getElementById('healthy-status-impact-filter');
    const resetBtn = document.getElementById('reset-filters-btn');

    let filterTimeout;
    const debouncedApplyFilters = () => {
        clearTimeout(filterTimeout);
        filterTimeout = setTimeout(applyFilters, 100);
    };

    [regionFilter, severityFilter, sectionFilter, impactFilter].forEach(filter => {
        if (filter) {
            filter.removeEventListener('change', debouncedApplyFilters);
            filter.addEventListener('change', debouncedApplyFilters);
        }
    });

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
    
    setTimeout(applyFilters, 50);
};

const applyFilters = () => {
    const regionValue = document.getElementById('healthy-status-region-filter')?.value || 'all';
    const severityValue = document.getElementById('healthy-status-severity-filter')?.value || 'all';
    const sectionValue = document.getElementById('healthy-status-section-filter')?.value || 'all';
    const impactValue = document.getElementById('healthy-status-impact-filter')?.value || 'all';

    let filteredFindings = [...(window.lastHealthyStatusFindings || [])];
    
    if (regionValue !== 'all') {
        filteredFindings = filteredFindings.filter(finding => {
            const resources = finding.affected_resources || [];
            if (resources.length === 0) return false;
            
            return resources.some(res => {
                if (typeof res === 'object' && res !== null) {
                    const region = res.region || 'Global';
                    return region === regionValue || region === 'Global';
                } else if (typeof res === 'string') {
                    return regionValue === 'Global';
                }
                return false;
            });
        });
    }
    
    if (severityValue !== 'all') {
        filteredFindings = filteredFindings.filter(finding => 
            finding.severity === severityValue
        );
    }
    
    if (sectionValue !== 'all') {
        filteredFindings = filteredFindings.filter(finding => 
            finding.section === sectionValue
        );
    }
    
    if (impactValue !== 'all') {
        filteredFindings = filteredFindings.filter(finding => 
            classifyFindingImpact(finding) === impactValue
        );
    }
    
    updateFindingsCount(filteredFindings.length, (window.lastHealthyStatusFindings || []).length);
    
    updateActiveFiltersDisplay();
    
    renderHealthyStatusFindings(filteredFindings);
};

const updateFindingsCount = (filtered, total) => {
    const countDisplay = document.getElementById('findings-count-display');
    if (countDisplay) {
        if (filtered === total) {
            countDisplay.innerHTML = `
                <div class="flex items-center space-x-1">
                    <svg class="w-4 h-4" fill="currentColor" viewBox="0 0 20 20">
                        <path fill-rule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zm3.707-9.293a1 1 0 00-1.414-1.414L9 10.586 7.707 9.293a1 1 0 00-1.414 1.414l2 2a1 1 0 001.414 0l4-4z" clip-rule="evenodd"></path>
                    </svg>
                    <span>${total} finding${total !== 1 ? 's' : ''}</span>
                </div>
            `;
            countDisplay.className = "bg-[#eb3496] text-white px-3 py-1 rounded-full text-sm font-semibold flex items-center";
        } else {
            countDisplay.innerHTML = `
                <div class="flex items-center space-x-1">
                    <svg class="w-4 h-4" fill="currentColor" viewBox="0 0 20 20">
                        <path fill-rule="evenodd" d="M3 3a1 1 0 011-1h12a1 1 0 011 1v3a1 1 0 01-.293.707L12 11.414V15a1 1 0 01-.293.707l-2 2A1 1 0 018 17v-5.586L3.293 6.707A1 1 0 013 6V3z" clip-rule="evenodd"></path>
                    </svg>
                    <span>${filtered}/${total}</span>
                </div>
            `;
            countDisplay.className = "bg-blue-500 text-white px-3 py-1 rounded-full text-sm font-semibold flex items-center animate-pulse";
        }
    }
};

const updateActiveFiltersDisplay = () => {
    const activeFiltersContainer = document.getElementById('active-filters-container');
    const activeFiltersDisplay = document.getElementById('active-filters-display');
    
    if (!activeFiltersContainer || !activeFiltersDisplay) return;
    
    activeFiltersContainer.innerHTML = '';
    let hasActiveFilters = false;
    
    const severityConfig = {
        'Crítico': { label: 'Critical', class: 'severity-pill-critical' },
        'Alto': { label: 'High', class: 'severity-pill-high' },
        'Medio': { label: 'Medium', class: 'severity-pill-medium' },
        'Bajo': { label: 'Low', class: 'severity-pill-low' },
        'Informativo': { label: 'Info', class: 'severity-pill-info' }
    };
    
    const impactConfig = {
        'compliance': { label: 'Compliance Risk', class: 'impact-pill-compliance' },
        'data_breach': { label: 'Data Breach Risk', class: 'impact-pill-data-breach' },
        'operational': { label: 'Operational Risk', class: 'impact-pill-operational' },
        'access_control': { label: 'Access Control Risk', class: 'impact-pill-access-control' },
        'monitoring': { label: 'Monitoring Gap', class: 'impact-pill-monitoring' },
        'encryption': { label: 'Encryption Issue', class: 'impact-pill-encryption' }
    };
    
    const regionValue = document.getElementById('healthy-status-region-filter')?.value;
    const severityValue = document.getElementById('healthy-status-severity-filter')?.value;
    const sectionValue = document.getElementById('healthy-status-section-filter')?.value;
    const impactValue = document.getElementById('healthy-status-impact-filter')?.value;
    
    if (regionValue && regionValue !== 'all') {
        const pill = createFilterPill('Region', regionValue, 'region', 'bg-blue-100 text-blue-800 border-blue-200');
        activeFiltersContainer.appendChild(pill);
        hasActiveFilters = true;
    }
    
    if (severityValue && severityValue !== 'all') {
        const config = severityConfig[severityValue];
        const pill = createFilterPill('Severity', config?.label || severityValue, 'severity', config?.class || 'bg-gray-100 text-gray-800 border-gray-200');
        activeFiltersContainer.appendChild(pill);
        hasActiveFilters = true;
    }
    
    if (sectionValue && sectionValue !== 'all') {
        const pill = createFilterPill('Section', sectionValue, 'section', 'bg-green-100 text-green-800 border-green-200');
        activeFiltersContainer.appendChild(pill);
        hasActiveFilters = true;
    }
    
    if (impactValue && impactValue !== 'all') {
        const config = impactConfig[impactValue];
        const pill = createFilterPill('Impact', config?.label || impactValue, 'impact', config?.class || 'bg-gray-100 text-gray-800 border-gray-200');
        activeFiltersContainer.appendChild(pill);
        hasActiveFilters = true;
    }
    
    if (hasActiveFilters) {
        activeFiltersDisplay.classList.remove('hidden');
    } else {
        activeFiltersDisplay.classList.add('hidden');
    }
};

const createFilterPill = (type, label, filterType, cssClass) => {
    const pill = document.createElement('div');
    pill.className = `filter-pill ${cssClass}`;
    pill.innerHTML = `
        <span class="text-xs font-medium opacity-75">${type}:</span>
        <span class="text-xs font-semibold">${label}</span>
        <button class="ml-1 hover:bg-black hover:bg-opacity-10 rounded-full p-0.5 transition-colors" onclick="removeFilter('${filterType}')">
            <svg class="w-3 h-3" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12"></path>
            </svg>
        </button>
    `;
    return pill;
};

const removeFilter = (filterType) => {
    const filterMap = {
        'region': 'healthy-status-region-filter',
        'severity': 'healthy-status-severity-filter',
        'section': 'healthy-status-section-filter',
        'impact': 'healthy-status-impact-filter'
    };
    
    const filterId = filterMap[filterType];
    const filter = document.getElementById(filterId);
    
    if (filter) {
        filter.value = 'all';
        applyFilters();
    }
};


// --- IMPACT CLASSIFICATION ---
const classifyFindingImpact = (finding) => {
    const name = (finding.name || '').toLowerCase();
    const description = (finding.description || '').toLowerCase();
    const section = (finding.section || '').toLowerCase();
    const ruleId = (finding.rule_id || '').toLowerCase();

    if (ruleId.includes('pci') || name.includes('pci') || description.includes('pci') ||
        name.includes('cis') || description.includes('compliance') || 
        description.includes('standard') || description.includes('benchmark')) {
        return 'compliance';
    }

    if (name.includes('public') || name.includes('exposed') || name.includes('internet') ||
        description.includes('public access') || description.includes('publicly accessible') ||
        section.includes('internet exposure') || name.includes('unencrypted')) {
        return 'data_breach';
    }

    if (section.includes('identity') || section.includes('access') || 
        name.includes('mfa') || name.includes('password') || name.includes('policy') ||
        name.includes('permission') || name.includes('role') || name.includes('user')) {
        return 'access_control';
    }

    if (section.includes('logging') || section.includes('monitoring') || 
        name.includes('cloudtrail') || name.includes('guardduty') || name.includes('log') ||
        name.includes('disabled') || name.includes('not enabled')) {
        return 'monitoring';
    }

    if (name.includes('encrypt') || name.includes('kms') || description.includes('encrypt') ||
        section.includes('data protection')) {
        return 'encryption';
    }

    return 'operational';
};

export const buildGeminiReportView = () => {
    const container = document.getElementById('hs-report-content');
    if (!container) return;

    const defaultPrompt = `Act as a senior cybersecurity consultant from [Your Company Name]. The recipient of this email is our client, an individual in a technical leadership role (CTO, Tech Lead).

Your task is to draft a clear and concise email to notify the client about the security findings identified in their AWS account.

The email must have the following structure:

**Subject:** Executive Summary: Security Findings in Your AWS Account

**Email Body:**

* **Greeting:** A professional salutation (e.g., "Dear [Client Name],").
* **Introduction (1 paragraph):** Briefly state that a security review has been completed and that the key results are presented below.
* **Summary of Findings:** Present a bulleted list. For **each type of finding** identified in the JSON I provide, include a bullet point with:
    * The **finding's title**.
    * In parentheses, its **severity**.
    * A **brief description (1-2 sentences)** of the associated business risk. **Do not include the detailed list of affected resources**, only a summary of the issue.
* **Primary Recommendation:** Based on the findings, offer a general, prioritized recommendation (e.g., "We recommend focusing initial efforts on remediating Critical and High severity findings, especially those related to identity and access management.").
* **Next Steps:** Propose scheduling a meeting to review the full technical report and coordinate the remediation plan.
* **Closing:** A cordial and professional closing.

The goal is for the client to quickly understand the existing issues and their impact without being overwhelmed by technical details in the first contact. Ensure that **all types of findings** are listed.

Below are the findings in JSON format:`;

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

export const check_healthy_status_rules = (auditData) => {
    const findings = [];
    
    try {
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
                <div class="flex items-center justify-center text-gray-500">
                    <svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" fill="currentColor" class="mr-3" viewBox="0 0 16 16">
                        <path d="M8 15A7 7 0 1 1 8 1a7 7 0 0 1 0 14zm0 1A8 8 0 1 0 8 0a8 8 0 0 0 0 16z"/>
                        <path d="M8 4a.905.905 0 0 0-.9.995l.35 3.507a.552.552 0 0 0 1.1 0l.35-3.507A.905.905 0 0 0 8 4zm.002 6a1 1 0 1 0 0 2 1 1 0 0 0 0-2z"/>
                    </svg>
                    <p class="text-center font-medium text-lg text-gray-600">No findings were found for the selected criteria.</p>
                </div>
            </div>
        `;
        return;
    }

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

        const severityToEnglish = {
            'Crítico': 'Critical',
            'Alto': 'High',
            'Medio': 'Medium',
            'Bajo': 'Low',
            'Informativo': 'Info'
        };
        const severityInEnglish = severityToEnglish[finding.severity] || finding.severity;

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

        const pciBadgeHtml = finding.pci_requirement 
            ? `<span class="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium bg-gray-100 text-gray-800 border border-gray-300">${finding.pci_requirement}</span>`
            : '';
        
        const card = `
            <div class="bg-white p-4 rounded-xl mb-4 border-l-4 ${borderColor} shadow-sm">
                <div class="flex flex-wrap items-center justify-between mb-2">
                    <h3 class="text-xl font-bold text-[#204071] flex-grow">${finding.name || 'Unknown finding'}</h3>
                    <div class="flex flex-wrap gap-2 mt-1 sm:mt-0">
                        <span class="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium ${severityBadgeColor}">${severityInEnglish || 'UNKNOWN'}</span>
                        <span class="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium bg-blue-50 text-blue-700">${impactLabel}</span>
                        ${pciBadgeHtml}
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
    const geminiRegionSelect = document.getElementById('gemini-region-filter');
    
    if (!regionSelect || !sectionSelect) return;

    const regions = new Set();
    
    (findings || []).forEach(finding => {
        (finding.affected_resources || []).forEach(res => {
            if (typeof res === 'object' && res !== null && res.region) {
                regions.add(res.region);
            } else {
                regions.add('Global');
            }
        });
    });

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
        
        if (geminiRegionSelect) {
            const geminiOption = document.createElement('option');
            geminiOption.value = region;
            geminiOption.textContent = region;
            geminiRegionSelect.appendChild(geminiOption);
        }
    });

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

    if (findings && findings.length > 0) {
        updateFindingsCount(findings.length, findings.length);
    }
};

export const initializeFiltersAfterDataLoad = (findings) => {
    window.lastHealthyStatusFindings = findings || [];
    
    populateHealthyStatusFilter(findings);
    
    renderHealthyStatusFindings(findings);
    
    setupFilterEventListeners();
};


/**
 * Construye la vista de inventario de recursos marcados (scoped) en una tabla unificada.
 */
export const buildScopedInventoryView = () => {
    const container = document.getElementById('hs-inventory-content');
    if (!container) return;

    const scopedResources = window.scopedResources || {};
    const arns = Object.keys(scopedResources);

    if (arns.length === 0) {
        container.innerHTML = `
            <div class="bg-white p-6 rounded-xl shadow-sm border border-gray-100">
                <p class="text-center text-gray-500">No resources have been marked as 'in scope' yet.</p>
                <p class="text-center text-xs text-gray-400 mt-2">You can mark resources in their respective sections (e.g., Compute, Databases).</p>
            </div>`;
        return;
    }

    // Unificar todos los recursos en una sola lista con un formato estándar
    const unifiedScopedItems = [];
    arns.forEach(arn => {
        const comment = scopedResources[arn].comment;
        const service = arn.split(':')[2];

        switch (service) {
            case 'ec2':
                const ec2Instance = window.computeApiData?.results?.ec2_instances.find(i => i.ARN === arn);
                if (ec2Instance) {
                    unifiedScopedItems.push({
                        type: 'EC2 Instance',
                        region: ec2Instance.Region,
                        identifier: ec2Instance.InstanceId,
                        details: `Public IP: ${ec2Instance.PublicIpAddress || '-'}`,
                        comment: comment,
                        arn: arn
                    });
                }
                break;
            case 'lambda':
                const lambdaFunc = window.computeApiData?.results?.lambda_functions.find(f => f.ARN === arn);
                if (lambdaFunc) {
                    unifiedScopedItems.push({
                        type: 'Lambda Function',
                        region: lambdaFunc.Region,
                        identifier: lambdaFunc.FunctionName,
                        details: `Runtime: ${lambdaFunc.Runtime}`,
                        comment: comment,
                        arn: arn
                    });
                }
                break;
            case 'rds':
                const rdsInstance = window.databasesApiData?.results?.rds_instances.find(db => db.ARN === arn);
                if (rdsInstance) {
                    unifiedScopedItems.push({
                        type: 'RDS Instance',
                        region: rdsInstance.Region,
                        identifier: rdsInstance.DBInstanceIdentifier,
                        details: `Public Access: ${rdsInstance.PubliclyAccessible ? '<span class="text-red-600 font-bold">YES</span>' : 'NO'}`,
                        comment: comment,
                        arn: arn
                    });
                }
                break;
            
            case 'secretsmanager':
                const secret = window.secretsManagerApiData?.results?.secrets.find(s => s.ARN === arn);
                if (secret) {
                    unifiedScopedItems.push({
                        type: 'Secret',
                        region: secret.Region,
                        identifier: secret.Name,
                        details: `Rotation: ${secret.RotationEnabled ? 'Enabled' : 'Disabled'}`,
                        comment: comment,
                        arn: arn
                    });
                }
                break;
            case 'kms':
                const kmsKey = window.kmsApiData?.results?.keys.find(k => k.ARN === arn);
                if (kmsKey) {
                    unifiedScopedItems.push({
                        type: 'KMS Key',
                        region: kmsKey.Region,
                        identifier: kmsKey.Aliases || kmsKey.KeyId,
                        details: `Manager: ${kmsKey.KeyManager}`,
                        comment: comment,
                        arn: arn
                    });
                }
                break;

            case 'acm':
                const certificate = window.acmApiData?.results?.certificates.find(c => c.CertificateArn === arn);
                if (certificate) {
                    unifiedScopedItems.push({
                        type: 'ACM Certificate',
                        region: certificate.Region,
                        identifier: certificate.DomainName,
                        details: `Status: ${certificate.Status}`,
                        comment: comment,
                        arn: arn
                    });
                }
                break;

        }
    });

    // Renderizar la tabla unificada
    container.innerHTML = renderUnifiedScopedInventoryTable(unifiedScopedItems);
    setupScopedInventoryEvents(unifiedScopedItems);
};

const renderUnifiedScopedInventoryTable = (items) => {
    let tableRows = items.map((item, index) => `
        <tr class="hover:bg-gray-50" data-item-index="${index}" data-arn="${item.arn}">
            <td class="px-4 py-4 whitespace-nowrap text-sm text-gray-600">${item.region}</td>
            <td class="px-4 py-4 whitespace-nowrap text-sm font-semibold text-gray-700">${item.type}</td>
            <td class="px-4 py-4 text-sm font-medium text-gray-800 break-all">${item.identifier}</td>
            <td class="px-4 py-4 whitespace-nowrap text-sm text-gray-600">${item.details}</td>
            <td class="px-4 py-4 text-sm text-gray-600">
                <span class="comment-display" data-index="${index}">${item.comment}</span>
                <input type="text" class="comment-input hidden w-full px-2 py-1 text-sm border border-gray-300 rounded" 
                    data-index="${index}" value="${item.comment}" />
            </td>
            <td class="px-4 py-4 whitespace-nowrap text-sm">
                <div class="flex space-x-2">
                    <button class="edit-btn text-blue-600 hover:text-blue-800" data-index="${index}" title="Edit">
                        <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" fill="currentColor" class="bi bi-pencil" viewBox="0 0 16 16">
                            <path d="M12.146.146a.5.5 0 0 1 .708 0l3 3a.5.5 0 0 1 0 .708l-10 10a.5.5 0 0 1-.168.11l-5 2a.5.5 0 0 1-.65-.65l2-5a.5.5 0 0 1 .11-.168zM11.207 2.5 13.5 4.793 14.793 3.5 12.5 1.207zm1.586 3L10.5 3.207 4 9.707V10h.5a.5.5 0 0 1 .5.5v.5h.5a.5.5 0 0 1 .5.5v.5h.293zm-9.761 5.175-.106.106-1.528 3.821 3.821-1.528.106-.106A.5.5 0 0 1 5 12.5V12h-.5a.5.5 0 0 1-.5-.5V11h-.5a.5.5 0 0 1-.468-.325"/>
                        </svg>
                    </button>
                    <button class="save-btn hidden text-green-600" data-index="${index}" title="Save">
                        <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" fill="currentColor" class="bi bi-check-lg" viewBox="0 0 16 16">
                            <path d="M12.736 3.97a.733.733 0 0 1 1.047 0c.286.289.29.756.01 1.05L7.88 12.01a.733.733 0 0 1-1.065.02L3.217 8.384a.757.757 0 0 1 0-1.06.733.733 0 0 1 1.047 0l3.052 3.093 5.4-6.425z"/>
                        </svg>
                    </button>
                    <button class="cancel-btn hidden text-gray-600" data-index="${index}" title="Cancel">
                        <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" fill="currentColor" class="bi bi-x-lg" viewBox="0 0 16 16">
                            <path d="M2.146 2.854a.5.5 0 1 1 .708-.708L8 7.293l5.146-5.147a.5.5 0 0 1 .708.708L8.707 8l5.147 5.146a.5.5 0 0 1-.708.708L8 8.707l-5.146 5.147a.5.5 0 0 1-.708-.708L7.293 8z"/>
                        </svg>
                    </button>
                    <button class="delete-btn text-red-600 hover:text-red-800" data-index="${index}" title="Delete">
                        <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" fill="currentColor" class="bi bi-trash" viewBox="0 0 16 16">
                            <path d="M5.5 5.5A.5.5 0 0 1 6 6v6a.5.5 0 0 1-1 0V6a.5.5 0 0 1 .5-.5m2.5 0a.5.5 0 0 1 .5.5v6a.5.5 0 0 1-1 0V6a.5.5 0 0 1 .5-.5m3 .5a.5.5 0 0 0-1 0v6a.5.5 0 0 0 1 0z"/>
                            <path d="M14.5 3a1 1 0 0 1-1 1H13v9a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V4h-.5a1 1 0 0 1-1-1V2a1 1 0 0 1 1-1H6a1 1 0 0 1 1-1h2a1 1 0 0 1 1 1h3.5a1 1 0 0 1 1 1zM4.118 4 4 4.059V13a1 1 0 0 0 1 1h6a1 1 0 0 0 1-1V4.059L11.882 4zM2.5 3h11V2h-11z"/>
                        </svg>
                    </button>
                </div>
            </td>
        </tr>
    `).join('');

    return `
    <div class="bg-white p-6 rounded-xl shadow-sm border border-gray-100 mb-6">
        <h3 class="font-bold text-lg mb-4 text-[#204071]">Scoped Resources Inventory</h3>
        <div class="overflow-x-auto">
            <table class="min-w-full divide-y divide-gray-200">
                <thead class="bg-gray-50">
                    <tr>
                        <th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Region</th>
                        <th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Type</th>
                        <th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Resource Identifier</th>
                        <th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Details</th>
                        <th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Reason for Scoping</th>
                        <th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Actions</th>
                    </tr>
                </thead>
                <tbody class="bg-white divide-y divide-gray-200">${tableRows}</tbody>
            </table>
        </div>
    </div>`;
};

export const buildAuditorNotesView = () => {
    const container = document.getElementById('hs-notes-content');
    if (!container) return;

    const notes = window.auditorNotes || [];

    if (notes.length === 0) {
        container.innerHTML = `
            <div class="bg-white p-6 rounded-xl shadow-sm border border-gray-100">
                <p class="text-center text-gray-500">You haven't written any notes yet.</p>
                <p class="text-center text-xs text-gray-400 mt-2">Click the floating pen icon to start documenting your findings.</p>
            </div>`;
        return;
    }

    const groupedNotes = notes.reduce((acc, note) => {
        const key = note.view || 'general';
        if (!acc[key]) {
            acc[key] = [];
        }
        acc[key].push(note);
        return acc;
    }, {});

    let html = '<div class="space-y-6 max-w-full overflow-x-hidden">';

    for (const view in groupedNotes) {
        const notesForView = groupedNotes[view].sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp));

        const viewLink = document.querySelector(`#sidebar-nav a[data-view="${view}"]`);
        const viewTitle = viewLink ? viewLink.querySelector('span div:last-child').textContent : view.replace('-', ' ').replace(/\b\w/g, l => l.toUpperCase());

        html += `
            <div class="bg-white p-5 rounded-xl shadow-sm border border-gray-100 max-w-full overflow-x-hidden">
                <h3 class="font-bold text-lg text-[#204071] mb-4 border-b pb-2">${viewTitle}</h3>
                <div class="space-y-4 max-w-full">
        `;

        notesForView.forEach(note => {
            const date = new Date(note.timestamp).toLocaleString();
            // Quitamos el replace de <br> aquí para el truncate
            const contentPreview = note.content.replace(/\n/g, ' '); 
            
            let arnHtml = '';
            if (note.arn) {
                arnHtml = `
                    <div class="mt-2 bg-gray-100 p-2 rounded-md max-w-full overflow-hidden">
                        <code class="text-xs text-gray-700 break-all block">
                            <span class="font-semibold">Resource:</span> ${note.arn}
                        </code>
                    </div>
                `;
            }

            let controlHtml = '';
            if (note.controlId) {
                controlHtml = `
                    <div class="mt-2 bg-yellow-50 p-2 rounded-md border-l-2 border-yellow-300 max-w-full overflow-hidden">
                        <code class="text-xs text-yellow-900 break-all block">
                            <span class="font-semibold">Control:</span> ${note.controlId}
                        </code>
                    </div>
                `;
            }

            html += `
                <div class="p-4 bg-blue-50/50 border-l-4 border-blue-300 rounded-r-lg shadow-sm cursor-pointer hover:shadow-md hover:border-blue-400 transition-shadow max-w-full overflow-hidden" 
                    onclick="window.showNoteDetails(${note.id})" style="word-break: break-word;">
                    <div class="flex justify-between items-start">
                        <h4 class="text-md font-bold text-gray-800 break-words max-w-[70%]">${note.title || 'Untitled Note'}</h4>
                        <p class="text-xs text-gray-500 flex-shrink-0 ml-4">${date}</p>
                    </div>
                    <p class="text-gray-700 text-sm mt-2 break-words overflow-hidden max-w-full" style="word-break: break-word;">${contentPreview}</p>
                    ${arnHtml}
                    ${controlHtml}
                </div>
            `;

        });

        html += '</div></div>';
    }

    html += '</div>';
    container.innerHTML = html;
};

window.removeFilter = removeFilter;

// Función para entrar en modo edición
const enterEditMode = (index) => {
    const commentDisplay = document.querySelector(`[data-index="${index}"].comment-display`);
    const commentInput = document.querySelector(`[data-index="${index}"].comment-input`);
    const editBtn = document.querySelector(`[data-index="${index}"].edit-btn`);
    const saveBtn = document.querySelector(`[data-index="${index}"].save-btn`);
    const cancelBtn = document.querySelector(`[data-index="${index}"].cancel-btn`);
    
    commentDisplay.classList.add('hidden');
    commentInput.classList.remove('hidden');
    editBtn.classList.add('hidden');
    saveBtn.classList.remove('hidden');
    cancelBtn.classList.remove('hidden');
    
    commentInput.focus();
};

// Función para guardar comentario
const saveComment = (index, items) => {
    const commentInput = document.querySelector(`[data-index="${index}"].comment-input`);
    const newComment = commentInput.value.trim();
    const arn = items[index].arn;
    
    updateScopedResourceComment(arn, newComment);
    refreshScopedInventory();
};

// Función para cancelar edición
const cancelEdit = (index, items) => {
    const originalComment = items[index].comment;
    const commentInput = document.querySelector(`[data-index="${index}"].comment-input`);
    commentInput.value = originalComment;
    exitEditMode(index);
};

// Función para salir del modo edición
const exitEditMode = (index) => {
    const commentDisplay = document.querySelector(`[data-index="${index}"].comment-display`);
    const commentInput = document.querySelector(`[data-index="${index}"].comment-input`);
    const editBtn = document.querySelector(`[data-index="${index}"].edit-btn`);
    const saveBtn = document.querySelector(`[data-index="${index}"].save-btn`);
    const cancelBtn = document.querySelector(`[data-index="${index}"].cancel-btn`);
    
    commentDisplay.classList.remove('hidden');
    commentInput.classList.add('hidden');
    editBtn.classList.remove('hidden');
    saveBtn.classList.add('hidden');
    cancelBtn.classList.add('hidden');
};

// Función para eliminar recurso
const deleteResource = (index, items) => {
    const arn = items[index].arn;
    const resourceName = items[index].identifier;
    
    if (confirm(`¿Seguro que quieres quitar "${resourceName}" del scope?`)) {
        removeScopedResource(arn);
        refreshScopedInventory();
    }
};

// Función para actualizar comentario
const updateScopedResourceComment = (arn, newComment) => {
    if (window.scopedResources[arn]) {
        window.scopedResources[arn].comment = newComment;
    }
};

// Función para eliminar recurso
const removeScopedResource = (arn) => {
    delete window.scopedResources[arn];
};

// Función para refrescar vista
const refreshScopedInventory = () => {
    buildScopedInventoryView();
};

const setupScopedInventoryEvents = (items) => {
    const container = document.getElementById('hs-inventory-content');
    if (!container) return;

    // Edit buttons
    container.querySelectorAll('.edit-btn').forEach(btn => {
        btn.addEventListener('click', (e) => {
            const index = e.currentTarget.getAttribute('data-index');
            enterEditMode(index);
        });
    });

    // Save buttons  
    container.querySelectorAll('.save-btn').forEach(btn => {
        btn.addEventListener('click', (e) => {
            const index = e.currentTarget.getAttribute('data-index');
            saveComment(index, items);
        });
    });

    // Cancel buttons
    container.querySelectorAll('.cancel-btn').forEach(btn => {
        btn.addEventListener('click', (e) => {
            const index = e.currentTarget.getAttribute('data-index');
            cancelEdit(index, items);
        });
    });

    // Delete buttons
    container.querySelectorAll('.delete-btn').forEach(btn => {
        btn.addEventListener('click', (e) => {
            const index = e.currentTarget.getAttribute('data-index');
            deleteResource(index, items);
        });
    });
};