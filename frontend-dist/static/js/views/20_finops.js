/**
 * 20_finops.js
 * Contiene la lógica para construir y renderizar la vista de FinOps.
 */
import { log } from '../utils.js';

// --- FUNCIÓN PRINCIPAL DE LA VISTA (EXPORTADA) ---
export const buildFinopsView = () => {
    const container = document.getElementById('finops-view');
    if (!container) return;

    // Si no hay datos, muestra la pantalla inicial con el botón para escanear.
    if (!window.finopsApiData) {
        container.innerHTML = renderInitialState();
        document.getElementById('run-finops-scan-btn').addEventListener('click', runFinopsScan);
    } else {
        // Si hay datos, renderiza los resultados.
        container.innerHTML = renderFinopsDashboard(window.finopsApiData.results);
    }
};

// --- LÓGICA DE ESCANEO ---
const runFinopsScan = async () => {
    log('Iniciando escaneo de FinOps...', 'info');
    const btn = document.getElementById('run-finops-scan-btn');
    const btnText = btn.querySelector('span');
    const spinner = btn.querySelector('div');

    btn.disabled = true;
    spinner.classList.remove('hidden');
    btnText.textContent = 'Analizando Desperdicio...';

    const accessKey = document.getElementById('access-key-input').value.trim();
    const secretKey = document.getElementById('secret-key-input').value.trim();
    const sessionToken = document.getElementById('session-token-input').value.trim();

    if (!accessKey || !secretKey) {
        alert('Por favor, introduce las credenciales de AWS primero.');
        btn.disabled = false;
        spinner.classList.add('hidden');
        btnText.textContent = 'Ejecutar Análisis FinOps';
        return;
    }

    const payload = { access_key: accessKey, secret_key: secretKey };
    if (sessionToken) payload.session_token = sessionToken;

    try {
        const response = await fetch('/api/run-finops-audit', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(payload)
        });

        const data = await response.json();
        if (!response.ok) throw new Error(data.error || 'Error en el escaneo de FinOps');

        window.finopsApiData = data;
        log('Escaneo de FinOps completado.', 'success');
        buildFinopsView(); // Vuelve a renderizar la vista con los nuevos datos

    } catch (error) {
        log(`Error en el escaneo de FinOps: ${error.message}`, 'error');
        alert(`Error: ${error.message}`);
    } finally {
        btn.disabled = false;
        spinner.classList.add('hidden');
        btnText.textContent = 'Ejecutar Análisis FinOps';
    }
};

// --- RENDERIZADO DE HTML ---

const renderInitialState = () => `
    <header class="flex justify-between items-center mb-6">
        <div>
            <h2 class="text-2xl font-bold text-[#204071]">FinOps - Identificación de Desperdicio</h2>
            <p class="text-sm text-gray-500">Encuentra recursos no utilizados para reducir tu factura de AWS.</p>
        </div>
    </header>
    <div class="text-center py-16 bg-white rounded-lg border border-gray-200">
        <svg xmlns="http://www.w3.org/2000/svg" fill="currentColor" class="mx-auto h-12 w-12 text-gray-400" viewBox="0 0 16 16">
            <path d="M4 3.06h2.726c1.22 0 2.12.575 2.325 1.724H4v1.051h5.051C8.855 7.001 8 7.558 6.788 7.558H4v1.317L8.437 14h2.11L6.095 8.884h.855c1.258 0 2.156.58 2.328 1.724h4.904V9.02H8.964c-.212-1.22.5-1.872 1.956-1.872h.855l.432 2.32H16v-1.05h-2.113c-.208-1.148-.925-1.724-2.328-1.724H8.964V4.784h2.11L14.47 14h1.53L12.447 3.06z"/>
        </svg>
        <h3 class="mt-2 text-lg font-medium text-[#204071]">Listo para Optimizar</h3>
        <p class="mt-1 text-sm text-gray-500">Ejecuta el análisis para encontrar oportunidades de ahorro.</p>
        <div class="mt-6">
            <button id="run-finops-scan-btn" class="bg-[#eb3496] text-white px-6 py-3 rounded-lg font-bold text-lg hover:bg-[#d42c86] transition flex items-center justify-center space-x-2 mx-auto">
                <span>Ejecutar Análisis FinOps</span>
                <div class="spinner hidden"></div>
            </button>
        </div>
    </div>
`;

const renderFinopsDashboard = (results) => {
    const { unattached_volumes, unassociated_eips, idle_load_balancers } = results;

    const totalSavings = (
        unattached_volumes.reduce((sum, item) => sum + item.EstimatedMonthlyCost, 0) +
        unassociated_eips.reduce((sum, item) => sum + item.EstimatedMonthlyCost, 0) +
        idle_load_balancers.reduce((sum, item) => sum + item.EstimatedMonthlyCost, 0)
    ).toFixed(2);
    
    return `
        <header class="flex justify-between items-center mb-6">
            <div>
                <h2 class="text-2xl font-bold text-[#204071]">Dashboard de Ahorros Potenciales</h2>
                <p class="text-sm text-gray-500">Ahorro total estimado: <span class="font-bold text-green-600 text-lg">$${totalSavings}/mes</span></p>
            </div>
            <button onclick="document.getElementById('run-finops-scan-btn').click()" class="bg-blue-600 text-white px-4 py-2 rounded-lg font-medium text-sm hover:bg-blue-700 transition">
                Volver a Analizar
            </button>
        </header>
        <div class="space-y-6">
            ${renderFindingCard('Volúmenes EBS sin adjuntar', unattached_volumes, ['ID de Volumen', 'Región', 'Tamaño (GB)'], ['VolumeId', 'Region', 'Size'])}
            ${renderFindingCard('IPs Elásticas no asociadas', unassociated_eips, ['IP Pública', 'Región', 'ID de Alocación'], ['PublicIp', 'Region', 'AllocationId'])}
            ${renderFindingCard('Balanceadores de Carga inactivos', idle_load_balancers, ['Nombre del LB', 'Región', 'Tipo'], ['LoadBalancerName', 'Region', 'Type'])}
        </div>
        <div class="mt-6 text-xs text-center text-gray-500">
            * Los costes son estimaciones basadas en precios de us-east-1 y pueden variar. Sirven como guía de magnitud del ahorro.
        </div>
    `;
};

const renderFindingCard = (title, items, headers, dataKeys) => {
    const totalCount = items.length;
    const totalSavings = items.reduce((sum, item) => sum + item.EstimatedMonthlyCost, 0).toFixed(2);
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
                        <p class="text-sm text-green-600 font-medium">¡Perfecto! No se encontraron recursos de este tipo.</p>
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
                    <p class="text-sm text-gray-500">${totalCount} recurso(s) encontrado(s).</p>
                </div>
                <div>
                    <p class="text-xl font-bold text-red-600">$${totalSavings}/mes</p>
                    <p class="text-xs text-gray-500 text-right">ahorro estimado</p>
                </div>
            </div>
            <div class="mt-4">
                <button onclick="document.getElementById('${cardId}-details').classList.toggle('hidden')" class="text-sm text-blue-600 hover:underline font-medium">
                    Ver/Ocultar Detalles
                </button>
            </div>
            <div id="${cardId}-details" class="mt-4 hidden overflow-x-auto">
                <table class="min-w-full divide-y divide-gray-200">
                    <thead class="bg-gray-50">
                        <tr>
                            ${headers.map(h => `<th class="px-4 py-2 text-left text-xs font-medium text-gray-500 uppercase">${h}</th>`).join('')}
                            <th class="px-4 py-2 text-left text-xs font-medium text-gray-500 uppercase">Coste/Mes Est.</th>
                        </tr>
                    </thead>
                    <tbody class="bg-white divide-y divide-gray-200">
                        ${items.map(item => `
                            <tr class="hover:bg-gray-50">
                                ${dataKeys.map(key => `<td class="px-4 py-3 whitespace-nowrap text-sm text-gray-700 font-mono">${item[key]}</td>`).join('')}
                                <td class="px-4 py-3 whitespace-nowrap text-sm text-red-600 font-mono">$${item.EstimatedMonthlyCost.toFixed(2)}</td>
                            </tr>
                        `).join('')}
                    </tbody>
                </table>
            </div>
        </div>
    `;
};