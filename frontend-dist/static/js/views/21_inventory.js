/**
 * 21_inventory.js
 * Contiene la lógica para la vista de inventario de recursos.
 */
import { log } from '../utils.js';

export const buildInventoryView = () => {
    const container = document.getElementById('inventory-view');
    if (!container) return;

    if (!window.inventoryApiData) {
        container.innerHTML = renderInitialState();
        document.getElementById('run-inventory-scan-btn').addEventListener('click', runInventoryScan);
    } else {
        container.innerHTML = renderInventoryTable(window.inventoryApiData.results);
    }
};

const runInventoryScan = async () => {
    log('Starting resource inventory scan...', 'info');
    const btn = document.getElementById('run-inventory-scan-btn');
    const btnText = btn.querySelector('span');
    const spinner = btn.querySelector('div');

    btn.disabled = true;
    spinner.classList.remove('hidden');
    btnText.textContent = 'Counting Resources...';

    const accessKey = document.getElementById('access-key-input').value.trim();
    const secretKey = document.getElementById('secret-key-input').value.trim();
    const sessionToken = document.getElementById('session-token-input').value.trim();

    if (!accessKey || !secretKey) {
        alert('Please enter AWS credentials first.');
        btn.disabled = false;
        spinner.classList.add('hidden');
        btnText.textContent = 'Run Inventory Scan';
        return;
    }

    const payload = { access_key: accessKey, secret_key: secretKey };
    if (sessionToken) payload.session_token = sessionToken;

    try {
        const response = await fetch('/api/run-inventory-audit', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(payload)
        });
        const data = await response.json();
        if (!response.ok) throw new Error(data.error || 'Inventory scan failed');

        window.inventoryApiData = data;
        log('Inventory scan completed.', 'success');
        buildInventoryView();

    } catch (error) {
        log(`Inventory scan error: ${error.message}`, 'error');
        alert(`Error: ${error.message}`);
    } finally {
        btn.disabled = false;
        spinner.classList.add('hidden');
        btnText.textContent = 'Run Inventory Scan';
    }
};

const renderInitialState = () => `
    <header class="mb-6">
        <h2 class="text-2xl font-bold text-[#204071]">Resource Inventory</h2>
        <p class="text-sm text-gray-500">Get a high-level count of the main resources in your AWS account.</p>
    </header>
    <div class="text-center py-16 bg-white rounded-lg border border-gray-200">
        <svg class="mx-auto h-12 w-12 text-gray-400" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 5H7a2 2 0 00-2 2v12a2 2 0 002 2h10a2 2 0 002-2V7a2 2 0 00-2-2h-2M9 5a2 2 0 002 2h2a2 2 0 002-2M9 5a2 2 0 012-2h2a2 2 0 012 2m-3 7h3m-3 4h3m-6-4h.01M9 16h.01"/></svg>
        <h3 class="mt-2 text-lg font-medium text-[#204071]">Ready to Count</h3>
        <p class="mt-1 text-sm text-gray-500">Run the scan to generate the resource summary.</p>
        <div class="mt-6">
            <button id="run-inventory-scan-btn" class="bg-[#eb3496] text-white px-6 py-3 rounded-lg font-bold text-lg hover:bg-[#d42c86] transition flex items-center justify-center space-x-2 mx-auto">
                <span>Run Inventory Scan</span>
                <div class="spinner hidden"></div>
            </button>
        </div>
    </div>
`;

// EN 21_inventory.js, REEMPLAZA ESTA FUNCIÓN ENTERA

const renderInventoryTable = (results) => {
    // Mapeo de claves técnicas a nombres amigables
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

    // 1. Descubrir todas las regiones únicas que tienen al menos un recurso.
    const allRegions = new Set();
    for (const key in results) {
        if (results[key] && results[key].by_region) {
            Object.keys(results[key].by_region).forEach(region => allRegions.add(region));
        }
    }
    const sortedRegions = Array.from(allRegions).sort();

    // 2. Construir las cabeceras de la tabla (dinámicas)
    let tableHeadersHtml = `
        <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Resource Type</th>
        <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Total</th>
    `;
    sortedRegions.forEach(region => {
        tableHeadersHtml += `<th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">${region}</th>`;
    });

    // 3. Construir las filas de la tabla
    let tableRowsHtml = '';
    for (const key in resourceNames) {
        const item = results[key];
        if (!item) continue;

        let row = `
            <tr class="hover:bg-gray-50">
                <td class="px-6 py-4 whitespace-nowrap text-sm font-medium text-gray-900">${resourceNames[key]}</td>
                <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-600 font-mono font-bold">${item.total}</td>
        `;
        
        // Para cada región en el encabezado, buscamos el conteo. Si no existe, ponemos 0.
        sortedRegions.forEach(region => {
            const count = item.by_region[region] || 0;
            row += `<td class="px-6 py-4 whitespace-nowrap text-sm text-gray-600 font-mono">${count}</td>`;
        });

        row += `</tr>`;
        tableRowsHtml += row;
    }

    // 4. Devolver la tabla completa
    return `
        <header class="flex justify-between items-center mb-6">
            <div>
                <h2 class="text-2xl font-bold text-[#204071]">Resource Inventory Summary</h2>
                <p class="text-sm text-gray-500">Total count of key resources and breakdown by region.</p>
            </div>
            <button onclick="document.getElementById('run-inventory-scan-btn').click()" class="bg-blue-600 text-white px-4 py-2 rounded-lg font-medium text-sm hover:bg-blue-700 transition">
                Rescan
            </button>
        </header>
        <div class="bg-white p-6 rounded-xl shadow-sm border border-gray-100 overflow-x-auto">
            <table class="min-w-full divide-y divide-gray-200">
                <thead class="bg-gray-50">
                    <tr>
                        ${tableHeadersHtml}
                    </tr>
                </thead>
                <tbody class="bg-white divide-y divide-gray-200">
                    ${tableRowsHtml}
                </tbody>
            </table>
        </div>
    `;
};