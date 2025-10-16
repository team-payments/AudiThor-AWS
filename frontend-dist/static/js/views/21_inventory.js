/**
 * 21_inventory.js
 * Contiene la lógica para la vista de inventario de recursos.
 * AHORA SE CARGA AUTOMÁTICAMENTE CON EL ESCANEO PRINCIPAL.
 */
import { log } from '../utils.js';

export const buildInventoryView = () => {
    const container = document.getElementById('inventory-view');
    if (!container) return;

    // Ya no hay estado inicial. Si no hay datos, muestra un mensaje.
    // Si hay datos, muestra la tabla directamente.
    if (!window.inventoryApiData || !window.inventoryApiData.results) {
        container.innerHTML = `
            <header class="mb-6">
                <h2 class="text-2xl font-bold text-[#204071]">Resource Inventory</h2>
            </header>
            <div class="bg-white p-6 rounded-xl border border-gray-100">
                <p class="text-center text-gray-500">No inventory data found. Run a "Scan Account" to populate this section.</p>
            </div>`;
    } else {
        container.innerHTML = renderInventoryTable(window.inventoryApiData.results);
    }
};

const renderInventoryTable = (results) => {
    const resourceNames = {
        'ec2_instances': "EC2 Instances",
        'rds_instances': "RDS Instances",
        's3_buckets': "S3 Buckets",
        'load_balancers': "Load Balancers (ALB/NLB)",
        'lambda_functions': "Lambda Functions",
        'iam_users': "IAM Users",
        'iam_roles': "IAM Roles",
        'iam_policies': "IAM Customer-Managed Policies",
    };

    const summary = results || {};
    let tableRowsHtml = '';

    for (const key in resourceNames) {
        const item = summary[key];
        if (!item) continue;

        let row = `
            <tr class="hover:bg-gray-50">
                <td class="px-6 py-4 whitespace-nowrap text-sm font-medium text-gray-900">${resourceNames[key]}</td>
                <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-600 font-mono font-bold">${item.total}</td>
        `;
        
        const sortedRegions = Object.keys(item.by_region).sort();
        sortedRegions.forEach(region => {
            row += `<td class="px-6 py-4 whitespace-nowrap text-sm text-gray-600 font-mono">${item.by_region[region] || 0}</td>`;
        });
        row += `</tr>`;
        tableRowsHtml += row;
    }

    const allRegions = new Set();
    for (const key in summary) {
        if (summary[key] && summary[key].by_region) {
            Object.keys(summary[key].by_region).forEach(region => allRegions.add(region));
        }
    }
    const sortedRegionsHeaders = Array.from(allRegions).sort();

    return `
        <header class="flex justify-between items-center mb-6">
            <div>
                <h2 class="text-2xl font-bold text-[#204071]">Resource Inventory Summary</h2>
                <p class="text-sm text-gray-500">Total count of key resources and breakdown by region.</p>
            </div>
        </header>
        <div class="bg-white p-6 rounded-xl shadow-sm border border-gray-100 overflow-x-auto">
            <table class="min-w-full divide-y divide-gray-200">
                <thead class="bg-gray-50">
                    <tr>
                        <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Resource Type</th>
                        <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Total</th>
                        ${sortedRegionsHeaders.map(region => `<th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">${region}</th>`).join('')}
                    </tr>
                </thead>
                <tbody class="bg-white divide-y divide-gray-200">
                    ${tableRowsHtml}
                </tbody>
            </table>
        </div>
    `;
};