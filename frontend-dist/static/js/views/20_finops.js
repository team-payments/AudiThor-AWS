/**
 * 20_finops.js
 * Contains the logic for building and rendering the FinOps view.
 */
import { log, handleTabClick } from '../utils.js';

// --- MAIN VIEW FUNCTION (EXPORTED) ---
export const buildFinopsView = () => {
    const container = document.getElementById('finops-view');
    if (!container) return;

    // Si no hay datos, muestra un mensaje para que el usuario ejecute el escaneo principal.
    if (!window.finopsApiData || !window.finopsApiData.results) {
        container.innerHTML = `
            <header class="mb-6">
                <h2 class="text-2xl font-bold text-[#204071]">FinOps Optimization</h2>
            </header>
            <div class="bg-white p-6 rounded-xl border border-gray-100">
                <p class="text-center text-gray-500">No FinOps data found. Run a "Scan Account" to populate this section.</p>
            </div>`;
    } else {
        // Si hay datos, renderiza el dashboard con pestañas.
        container.innerHTML = renderFinopsTabs();
        renderWasteDashboard(window.finopsApiData.results);
        renderModernizationDashboard(window.finopsApiData.results);
        
        const tabsNav = container.querySelector('#finops-tabs');
        if (tabsNav) {
            tabsNav.addEventListener('click', handleTabClick(tabsNav, '.finops-tab-content'));
        }
    }
};

// --- Renders the main shell of the dashboard (header, tabs) ---
const renderFinopsTabs = () => {
    const results = window.finopsApiData.results || {};
    
    // Calculate total savings from all quantifiable sources.
    const totalSavings = (
        (results.unattached_volumes || []).reduce((sum, item) => sum + item.EstimatedMonthlyCost, 0) +
        (results.unassociated_eips || []).reduce((sum, item) => sum + item.EstimatedMonthlyCost, 0) +
        (results.idle_load_balancers || []).reduce((sum, item) => sum + item.EstimatedMonthlyCost, 0) +
        (results.gp2_volumes || []).reduce((sum, item) => sum + item.EstimatedMonthlySavings, 0)
    ).toFixed(2);

    return `
        <header class="flex justify-between items-center mb-6">
            <div>
                <h2 class="text-2xl font-bold text-[#204071]">FinOps Optimization Dashboard</h2>
                <p class="text-sm text-gray-500">Estimated Quantifiable Savings: <span class="font-bold text-green-600 text-lg">$${totalSavings}/month</span></p>
            </div>
            <button onclick="document.getElementById('run-analysis-button').click()" class="bg-blue-600 text-white px-4 py-2 rounded-lg font-medium text-sm hover:bg-blue-700 transition">
                Rescan Account
            </button>
        </header>
        
        <div class="border-b border-gray-200 mb-6">
            <nav class="-mb-px flex space-x-6" id="finops-tabs">
                <a href="#" data-tab="finops-waste-content" class="tab-link py-3 px-1 border-b-2 border-[#eb3496] text-[#eb3496] font-semibold text-sm">Waste Identification</a>
                <a href="#" data-tab="finops-modernization-content" class="tab-link py-3 px-1 border-b-2 border-transparent text-gray-500 hover:text-gray-700 font-medium text-sm">Modernization & Efficiency</a>
            </nav>
        </div>

        <div id="finops-tab-content-container">
            <div id="finops-waste-content" class="finops-tab-content"></div>
            <div id="finops-modernization-content" class="finops-tab-content hidden"></div>
        </div>

        <div class="mt-6 text-xs text-center text-gray-500">
            * Costs are estimates based on us-east-1 pricing and may vary.
        </div>
    `;
};

// --- Renders the content for the "Waste Identification" tab ---
const renderWasteDashboard = (results) => {
    const container = document.getElementById('finops-waste-content');
    if (!container) return;
    
    // Defensive coding: if results or keys don't exist, use empty arrays to prevent errors.
    const { unattached_volumes = [], unassociated_eips = [], idle_load_balancers = [] } = results || {};
    
    container.innerHTML = `
        <div class="space-y-6">
            ${renderFindingCard({ title: 'Unattached EBS Volumes', items: unattached_volumes, headers: ['Volume ID', 'Region', 'Size (GB)'], dataKeys: ['VolumeId', 'Region', 'Size'] })}
            ${renderFindingCard({ title: 'Unassociated Elastic IPs', items: unassociated_eips, headers: ['Public IP', 'Region', 'Allocation ID'], dataKeys: ['PublicIp', 'Region', 'AllocationId'] })}
            ${renderFindingCard({ title: 'Inactive Load Balancers', items: idle_load_balancers, headers: ['LB Name', 'Region', 'Type'], dataKeys: ['LoadBalancerName', 'Region', 'Type'] })}
        </div>
    `;
};

// --- Renders the content for the "Modernization & Efficiency" tab ---
const renderModernizationDashboard = (results) => {
    const container = document.getElementById('finops-modernization-content');
    if (!container) return;

    // Defensive coding: if results or keys don't exist, use empty arrays.
    const { outdated_instances = [], gp2_volumes = [], s3_opportunities = [] } = results || {};

    container.innerHTML = `
        <div class="space-y-6">
            ${renderFindingCard({ title: 'EBS Volumes (gp2)', items: gp2_volumes, headers: ['Volume ID', 'Region', 'Size (GB)'], dataKeys: ['VolumeId', 'Region', 'Size'], savingsKey: 'EstimatedMonthlySavings' })}
            ${renderFindingCard({ title: 'Outdated EC2 Instances', items: outdated_instances, headers: ['Instance ID', 'Region', 'Current Type'], dataKeys: ['InstanceId', 'Region', 'InstanceType'], savingsKey: 'EstimatedSavings' })}
            ${renderFindingCard({ title: 'S3 Storage Optimization', items: s3_opportunities, headers: ['Bucket Name'], dataKeys: ['BucketName'], savingsKey: 'EstimatedSavings' })}
        </div>
    `;
};

// --- Renders a single finding card (reusable component) ---
const renderFindingCard = ({ title, items, headers, dataKeys, savingsKey = 'EstimatedMonthlyCost' }) => {
    const totalCount = items.length;
    const totalSavings = items.reduce((sum, item) => {
        const savings = item[savingsKey];
        return sum + (typeof savings === 'number' ? savings : 0);
    }, 0).toFixed(2);
    
    const cardId = title.toLowerCase().replace(/\s/g, '-');

    if (totalCount === 0) {
        return `
            <div class="bg-white p-6 rounded-xl border border-gray-100">
                <div class="flex items-center">
                    <div class="bg-green-100 p-3 rounded-full mr-4">
                        <svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" fill="currentColor" class="text-green-600" viewBox="0 0 16 16"><path d="M16 8A8 8 0 1 1 0 8a8 8 0 0 1 16 0zm-3.97-3.03a.75.75 0 0 0-1.08.022L7.477 9.417 5.384 7.323a.75.75 0 0 0-1.06 1.06L6.97 11.03a.75.75 0 0 0 1.079-.02l3.992-4.99a.75.75 0 0 0-.01-1.05z"/></svg>
                    </div>
                    <div>
                        <h3 class="font-bold text-lg text-gray-800">${title}</h3>
                        <p class="text-sm text-green-600 font-medium">All good! No resources of this type were found.</p>
                    </div>
                </div>
            </div>
        `;
    }

    return `
        <div class="bg-white p-6 rounded-xl shadow-sm border border-gray-100">
            <div class="flex justify-between items-start">
                <div>
                    <h3 class="font-bold text-lg text-[#204071]">${title}</h3>
                    <p class="text-sm text-gray-500">${totalCount} resource(s) found.</p>
                </div>
                ${totalSavings > 0 ? `
                <div>
                    <p class="text-xl font-bold text-green-600">$${totalSavings}/month</p>
                    <p class="text-xs text-gray-500 text-right">estimated savings</p>
                </div>` : ''}
            </div>
            <div class="mt-4">
                <button onclick="document.getElementById('${cardId}-details').classList.toggle('hidden')" class="text-sm text-blue-600 hover:underline font-medium">
                    Show/Hide Details
                </button>
            </div>
            <div id="${cardId}-details" class="mt-4 hidden overflow-x-auto">
                <table class="min-w-full divide-y divide-gray-200">
                    <thead class="bg-gray-50">
                        <tr>
                            ${headers.map(h => `<th class="px-4 py-2 text-left text-xs font-medium text-gray-500 uppercase">${h}</th>`).join('')}
                            <th class="px-4 py-2 text-left text-xs font-medium text-gray-500 uppercase">Recommendation / Savings</th>
                        </tr>
                    </thead>
                    <tbody class="bg-white divide-y divide-gray-200">
                        ${items.map(item => `
                            <tr class="hover:bg-gray-50">
                                ${dataKeys.map(key => `<td class="px-4 py-3 whitespace-nowrap text-sm text-gray-700 font-mono">${item[key]}</td>`).join('')}
                                <td class="px-4 py-3 text-sm text-gray-700">
                                    <p class="font-medium">${item.Recommendation}</p>
                                    ${typeof item[savingsKey] === 'number' ? `<p class="text-green-600 font-mono">$${item[savingsKey].toFixed(2)}/month</p>` : `<p class="text-blue-600">${item[savingsKey]}</p>`}
                                </td>
                            </tr>
                        `).join('')}
                    </tbody>
                </table>
            </div>
        </div>
    `;
};
