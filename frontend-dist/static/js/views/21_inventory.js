/**
 * 21_inventory.js
 * Contiene la lógica para la vista de inventario de recursos.
 * AHORA SE CARGA AUTOMÁTICAMENTE CON EL ESCANEO PRINCIPAL.
 */
import { log } from '../utils.js';

export const buildInventoryView = () => {
    const container = document.getElementById('inventory-view');
    if (!container) return;

    if (!window.inventoryApiData || !window.inventoryApiData.results) {
        container.innerHTML = `
            <div class="bg-white p-8 rounded-xl border border-gray-100 text-center max-w-4xl mx-auto">
                <h2 class="text-2xl font-bold text-[#204071]">Welcome to the Resource Inventory</h2>
                <p class="mt-2 text-gray-600">This is your central hub for visualizing AWS resources. To get started, you have two options:</p>

                <div class="mt-6 flex flex-col md:flex-row justify-center gap-6 text-left">
                    <div class="p-6 border rounded-lg md:w-1/2 bg-gray-50">
                        <h3 class="font-semibold text-lg text-[#204071]">Perform a Live Scan</h3>
                        <p class="text-sm text-gray-500 mt-1">Enter temporary AWS credentials in the top bar and click the <strong>"Scan Account"</strong> button to run a new security analysis.</p>
                    </div>
                    <div class="p-6 border rounded-lg md:w-1/2 bg-gray-50">
                        <h3 class="font-semibold text-lg text-[#204071]">Import Existing Results</h3>
                        <p class="text-sm text-gray-500 mt-1">Click the <strong>"Import"</strong> button to load a previously saved analysis from a <code>.json</code> file and instantly explore the findings.</p>
                    </div>
                </div>

                <div class="mt-10 pt-6 border-t border-gray-200">
                    <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" fill="currentColor" class="mx-auto mb-3 h-8 w-8 text-gray-500" viewBox="0 0 16 16">
                        <path d="M6 12.5a.5.5 0 0 1 .5-.5h3a.5.5 0 0 1 0 1h-3a.5.5 0 0 1-.5-.5M3 8.062C3 6.76 4.235 5.765 5.53 5.886a26.6 26.6 0 0 0 4.94 0C11.765 5.765 13 6.76 13 8.062v1.157a.93.93 0 0 1-.765.935c-.845.147-2.34.346-4.235.346s-3.39-.2-4.235-.346A.93.93 0 0 1 3 9.219zm4.542-.827a.25.25 0 0 0-.217.068l-.92.9a25 25 0 0 1-1.871-.183.25.25 0 0 0-.068.495c.55.076 1.232.149 2.02.193a.25.25 0 0 0 .189-.071l.754-.736.847 1.71a.25.25 0 0 0 .404.062l.932-.97a25 25 0 0 0 1.922-.188.25.25 0 0 0-.068-.495c-.538.074-1.207.145-1.98.189a.25.25 0 0 0-.166.076l-.754.785-.842-1.7a.25.25 0 0 0-.182-.135"/>
                        <path d="M8.5 1.866a1 1 0 1 0-1 0V3h-2A4.5 4.5 0 0 0 1 7.5V8a1 1 0 0 0-1 1v2a1 1 0 0 0 1 1v1a2 2 0 0 0 2 2h10a2 2 0 0 0 2-2v-1a1 1 0 0 0 1-1V9a1 1 0 0 0-1-1v-.5A4.5 4.5 0 0 0 10.5 3h-2zM14 7.5V13a1 1 0 0 1-1 1H3a1 1 0 0 1-1-1V7.5A3.5 3.5 0 0 1 5.5 4h5A3.5 3.5 0 0 1 14 7.5"/>
                    </svg>
                    <blockquote class="italic text-gray-600">"You have a robot army at your disposal, for free. Use them."</blockquote>
                    <p class="mt-1 text-sm text-gray-500">&mdash; Naval Ravikant</p>
                </div>
            </div>
        `;
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
        'vpcs': "VPCs",
        'dynamodb_tables': "DynamoDB Tables",
        'route53_hosted_zones': "Route 53 Hosted Zones",
    };

    const summary = results || {};
    let tableRowsHtml = '';

    // 1. Calcula la lista maestra de cabeceras de regiones activas
    const regionCounts = {};
    for (const key in summary) {
        if (summary[key] && summary[key].by_region) {
            for (const region in summary[key].by_region) {
                if (!regionCounts[region]) {
                    regionCounts[region] = 0;
                }
                regionCounts[region] += summary[key].by_region[region];
            }
        }
    }

    const activeRegions = Object.keys(regionCounts).filter(region =>
        region === 'Global' || regionCounts[region] > 0
    );
    const sortedRegionsHeaders = activeRegions.sort((a, b) => {
        if (a === 'Global') return -1; // 'Global' siempre primero
        if (b === 'Global') return 1;
        return regionCounts[b] - regionCounts[a];
    });

    // 2. Construye las filas (tbody) usando esa misma lista de cabeceras
    for (const key in resourceNames) {
        const item = summary[key];
        if (!item) continue;

        // Itera sobre la lista de cabeceras para generar las celdas de datos regionales
        const regionalCells = sortedRegionsHeaders.map(region => {
            const count = (item.by_region && item.by_region[region]) ? item.by_region[region] : 0;
            return `<td class="px-6 py-4 whitespace-nowrap text-sm text-gray-600 font-mono">${count}</td>`;
        }).join('');

        tableRowsHtml += `
            <tr class="hover:bg-gray-50">
                <td class="px-6 py-4 whitespace-nowrap text-sm font-medium text-gray-900">${resourceNames[key]}</td>
                <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-600 font-mono font-bold">${item.total}</td>
                ${regionalCells}
            </tr>
        `;
    }

    // 3. Devuelve el HTML final de la tabla completa
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