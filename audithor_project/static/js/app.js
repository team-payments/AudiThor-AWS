/**
 * app.js
 * Fichero principal (el "cerebro") de la lógica de la aplicación AudiThor.
 */

// 1. IMPORTACIONES
import { 
    log, 
    copyToClipboard, 
    handleTabClick, 
    createStatusBadge, 
    createAlarmStateBadge, 
    setupModalControls, 
    setupPagination, 
    renderSecurityHubFindings 
} from '/static/js/utils.js';

import { 
    buildIamView, 
    updateSecurityHubDashboard, 
    openModalWithSsoDetails, 
    openModalWithAccessKeyDetails, 
    openModalWithUserGroups,
    openModalWithUserRoles
} from '/static/js/views/01_iam.js';
import { buildExposureView } from '/static/js/views/02_exposure.js';
import { buildGuarddutyView } from '/static/js/views/03_guardduty.js';
import { buildEcrView } from '/static/js/views/04_ecr.js';
import { buildWafView } from '/static/js/views/05_waf.js';
import { buildCloudtrailView } from '/static/js/views/06_cloudtrail.js';
import { buildCloudwatchView } from '/static/js/views/07_cloudwatch.js';
import { buildInspectorView } from '/static/js/views/08_inspector.js';
import { buildAcmView } from '/static/js/views/09_acm.js';
import { buildComputeView } from '/static/js/views/10_compute.js';
import { buildDatabasesView } from '/static/js/views/11_databases.js';
import { buildKmsSecretsView } from '/static/js/views/12_kms_secrets.js';
import { buildNetworkPoliciesView } from '/static/js/views/13_network_policies.js';
import { buildConnectivityView } from '/static/js/views/14_connectivity.js';
import { buildConfigSHView } from '/static/js/views/15_config_sh.js';
import { buildCodePipelineView } from '/static/js/views/18_codepipeline.js';
import { buildPlaygroundView } from '/static/js/views/16_playground.js';
import { buildHealthyStatusView, buildGeminiReportView, buildScopedInventoryView, buildAuditorNotesView } from '/static/js/views/17_healthy_status.js';


// Importar las funciones que se usarán en onclick
import { openModalWithTlsDetails } from '/static/js/views/02_exposure.js';
import { openModalWithEcrPolicy } from '/static/js/views/04_ecr.js';
import { openModalWithKmsPolicy, openModalWithSecretDetails } from '/static/js/views/12_kms_secrets.js';
import { showCloudtrailEventDetails } from '/static/js/views/06_cloudtrail.js';
import { toggleAlarmDetails } from '/static/js/views/07_cloudwatch.js';
import { openModalWithEc2Tags, openModalWithLambdaTags, openModalWithLambdaRole } from '/static/js/views/10_compute.js';

// Importar iconos
import { SIDEBAR_ICONS } from '/static/js/icons.js';

// 2. ESTADO GLOBAL
window.iamApiData = null;
window.federationApiData = null;
window.accessAnalyzerApiData = null;
window.securityHubApiData = null;
window.exposureApiData = null;
window.guarddutyApiData = null;
window.wafApiData = null;
window.cloudtrailApiData = null;
window.cloudwatchApiData = null;
window.inspectorApiData = null;
window.acmApiData = null;
window.computeApiData = null;
window.ecrApiData = null;
window.databasesApiData = null;
window.networkPoliciesApiData = null;
window.connectivityApiData = null;
window.codepipelineApiData = null;
window.playgroundApiData = null;
window.configSHApiData = null;
window.configSHStatusApiData = null;
window.kmsApiData = null;
window.allAvailableRegions = [];
window.lastCloudtrailLookupResults = [];
window.lastHealthyStatusFindings = [];
window.trailAlertsData = null;
window.scopedResources = {};
window.auditorNotes = [];

// 3. SELECTORES
let views, mainNavLinks, runAnalysisBtn, accessKeyInput, secretKeyInput, sessionTokenInput, loadingSpinner, buttonText, errorMessageDiv, logContainer, clearLogBtn, toggleLogBtn, logPanel;

// 4. LÓGICA PRINCIPAL
const loadSidebarIcons = () => {
    const sidebarNav = document.getElementById('sidebar-nav');
    if (!sidebarNav) return;

    const navLinks = sidebarNav.querySelectorAll('a[data-view]');
    navLinks.forEach(link => {
        const viewName = link.dataset.view;
        const iconKey = viewName === 'healthy-status' ? 'healthy-status' : viewName;
        
        if (SIDEBAR_ICONS[iconKey]) {
            const span = link.querySelector('span');
            if (span) {
                const currentText = span.textContent.trim();
                
                // Crear nueva estructura: icono + texto en contenedores separados
                span.innerHTML = '';
                
                // Crear contenedor para el icono
                const iconDiv = document.createElement('div');
                iconDiv.innerHTML = SIDEBAR_ICONS[iconKey];
                iconDiv.className = 'flex-shrink-0';
                
                // Crear contenedor para el texto
                const textDiv = document.createElement('div');
                textDiv.textContent = currentText;
                textDiv.className = 'ml-3';
                
                // Añadir ambos al span
                span.appendChild(iconDiv);
                span.appendChild(textDiv);
                
                // Asegurar que el span tenga flex
                span.className = 'flex items-center';
            }
        }
    });
};

// --- NUEVO: FUNCIONES DE GESTIÓN DE SCOPE ---
const SCOPE_STORAGE_KEY = 'audiThorScopedResources';

const loadScopedResources = () => {
    const stored = localStorage.getItem(SCOPE_STORAGE_KEY);
    window.scopedResources = stored ? JSON.parse(stored) : {};
    log(`${Object.keys(window.scopedResources).length} recursos marcados cargados desde localStorage.`, 'info');
};

const saveScopedResources = () => {
    localStorage.setItem(SCOPE_STORAGE_KEY, JSON.stringify(window.scopedResources));
};

const setResourceScope = (arn, comment) => {
    if (arn && comment) {
        window.scopedResources[arn] = { comment: comment };
        log(`Recurso ${arn} marcado como 'in scope'.`, 'success');
    }
    saveScopedResources();
    rerenderCurrentView(); // Función para refrescar la vista actual
};

const removeResourceScope = (arn) => {
    if (arn && window.scopedResources[arn]) {
        delete window.scopedResources[arn];
        log(`Recurso ${arn} desmarcado.`, 'info');
    }
    saveScopedResources();
    rerenderCurrentView(); // Función para refrescar la vista actual
};


const NOTES_STORAGE_KEY = 'audiThorAuditorNotes';

const loadAuditorNotes = () => {
    const stored = localStorage.getItem(NOTES_STORAGE_KEY);
    try {
        window.auditorNotes = stored ? JSON.parse(stored) : [];
        log(`${window.auditorNotes.length} notas del auditor cargadas.`, 'info');
    } catch (error) {
        log(`Error al parsear las notas desde localStorage: ${error.message}. Se reiniciarán las notas.`, 'error');
        console.error("Datos de notas corruptos en localStorage:", stored);
        window.auditorNotes = [];
        localStorage.removeItem(NOTES_STORAGE_KEY);
    }
};


const saveAuditorNotes = () => {
    localStorage.setItem(NOTES_STORAGE_KEY, JSON.stringify(window.auditorNotes));
};

const saveAuditorNote = (noteContent, view, tab) => {
    const newNote = {
        id: Date.now(),
        view: view,
        tab: tab,
        timestamp: new Date().toISOString(),
        content: noteContent
    };
    window.auditorNotes.push(newNote);
    saveAuditorNotes(); 
    log(`Nota guardada para ${view}/${tab}.`, 'success');
    
    // Actualizar siempre la vista de notas, independientemente de dónde estemos
    buildAuditorNotesView();
};

const openNotesModal = () => {
    const modal = document.getElementById('notes-modal');
    const title = document.getElementById('notes-modal-title');
    const textarea = document.getElementById('notes-modal-textarea');
    const saveBtn = document.getElementById('notes-modal-save-btn');
    const cancelBtn = document.getElementById('notes-modal-cancel-btn');

    if (!modal) return;

    // Capturar contexto
    const activeViewLink = document.querySelector('#sidebar-nav a.bg-\\[\\#eb3496\\]');
    const viewName = activeViewLink ? activeViewLink.dataset.view : 'unknown';
    const viewText = activeViewLink ? activeViewLink.querySelector('span div:last-child').textContent : 'Unknown';

    const activeViewContainer = document.getElementById(`${viewName}-view`);
    let tabName = 'main';
    let tabText = 'Main';
    if (activeViewContainer) {
        const activeTabLink = activeViewContainer.querySelector('.tab-link.border-\\[\\#eb3496\\]');
        if (activeTabLink) {
            tabName = activeTabLink.dataset.tab;
            tabText = activeTabLink.textContent.split('(')[0].trim();
        }
    }

    title.textContent = `New Note for: ${viewText} / ${tabText}`;
    textarea.value = '';

    const handleSave = () => {
        if (textarea.value.trim()) {
            saveAuditorNote(textarea.value.trim(), viewName, tabName);
            modal.classList.add('hidden');
        }
    };

    // Limpiar listeners para evitar duplicados
    const newSaveBtn = saveBtn.cloneNode(true);
    saveBtn.parentNode.replaceChild(newSaveBtn, saveBtn);
    newSaveBtn.addEventListener('click', handleSave);

    cancelBtn.onclick = () => modal.classList.add('hidden');

    modal.classList.remove('hidden');
    textarea.focus();
};


// Refresca la vista activa para que los cambios de scope se reflejen inmediatamente
const rerenderCurrentView = () => {
    const activeLink = document.querySelector('#sidebar-nav a.bg-\\[\\#eb3496\\]');
    if (!activeLink) return;
    const viewName = activeLink.dataset.view;
    
    // Mapeo de nombre de vista a función de renderizado
    const viewBuilderMap = {
        'iam': buildIamView,
        'exposure': buildExposureView,
        'compute': buildComputeView,
        'databases': buildDatabasesView,
        'kms': buildKmsSecretsView,
        'healthy-status': buildHealthyStatusView,
    };

    if (viewBuilderMap[viewName]) {
        log(`Refrescando vista '${viewName}' para actualizar el scope...`, 'info');
        viewBuilderMap[viewName]();
    }
};

// Función para abrir y manejar el modal de scope
const openScopeModal = (arn, currentComment = '') => {
    const modal = document.getElementById('scope-modal');
    const title = document.getElementById('scope-modal-title');
    const textarea = document.getElementById('scope-comment-textarea');
    const saveBtn = document.getElementById('scope-modal-save-btn');
    const unscopeBtn = document.getElementById('scope-modal-unscope-btn');
    const closeBtn = document.getElementById('scope-modal-close-btn');

    if (!modal) return;

    title.textContent = `Marcar Recurso: ${arn.split('/').pop()}`;
    textarea.value = decodeURIComponent(currentComment);

    // Limpiar listeners antiguos para evitar ejecuciones múltiples
    const newSaveBtn = saveBtn.cloneNode(true);
    saveBtn.parentNode.replaceChild(newSaveBtn, saveBtn);

    const newUnscopeBtn = unscopeBtn.cloneNode(true);
    unscopeBtn.parentNode.replaceChild(newUnscopeBtn, unscopeBtn);

    newSaveBtn.addEventListener('click', () => {
        setResourceScope(arn, textarea.value);
        modal.classList.add('hidden');
    });

    newUnscopeBtn.addEventListener('click', () => {
        removeResourceScope(arn);
        modal.classList.add('hidden');
    });

    closeBtn.onclick = () => modal.classList.add('hidden');

    modal.classList.remove('hidden');
    textarea.focus();
};



const handleMainNavClick = (e) => {
    e.preventDefault();
    const link = e.target.closest('a.main-nav-link');
    if (!link) return;
    
    const targetView = link.dataset.view;
    if (!targetView) return;
    
    // Actualizar navegación activa
    mainNavLinks.forEach(l => {
        l.classList.remove('bg-[#eb3496]');
        l.classList.add('hover:bg-[#1a335a]');
    });
    link.classList.add('bg-[#eb3496]');
    link.classList.remove('hover:bg-[#1a335a]');
    
    // Mostrar vista correspondiente
    views.forEach(v => v.classList.add('hidden'));
    const targetViewElement = document.getElementById(`${targetView}-view`);
    if (targetViewElement) {
        targetViewElement.classList.remove('hidden');
    }
    if (targetView === 'healthy-status') {
        log('Refreshing scoped inventory view...', 'info');
        buildScopedInventoryView();
        buildAuditorNotesView();
    }
};

const runAnalysisFromInputs = async () => {
    // Resetear estado
    window.iamApiData = null; window.securityHubApiData = null; window.exposureApiData = null; window.guarddutyApiData = null; window.wafApiData = null; window.cloudtrailApiData = null; window.cloudwatchApiData = null; window.inspectorApiData = null; window.acmApiData = null; window.computeApiData = null; window.databasesApiData = null; window.networkPoliciesApiData = null; window.connectivityApiData = null; window.playgroundApiData = null; window.allAvailableRegions = []; window.lastCloudtrailLookupResults = []; window.federationApiData = null; window.configSHApiData = null; window.configSHStatusApiData = null; window.kmsApiData = null; window.ecrApiData = null; window.codepipelineApiData = null; window.secretsManagerApiData = null;
    document.querySelectorAll('.view').forEach(v => v.innerHTML = '');
    document.getElementById('iam-view').innerHTML = createInitialEmptyState();
    
    log('Starting full analysis...', 'info');
    const accessKey = accessKeyInput.value.trim(); 
    const secretKey = secretKeyInput.value.trim(); 
    const sessionToken = sessionTokenInput.value.trim();
    if (!accessKey || !secretKey) { 
        const msg = 'Please enter the Access Key ID and Secret Access Key.'; 
        errorMessageDiv.textContent = msg; 
        errorMessageDiv.classList.remove('hidden'); 
        log(msg, 'error'); 
        return; 
    }
    const payload = { access_key: accessKey, secret_key: secretKey };
    if (sessionToken) { payload.session_token = sessionToken; }
    
    runAnalysisBtn.disabled = true; 
    loadingSpinner.classList.remove('hidden'); 
    buttonText.textContent = 'Scanning...'; 
    errorMessageDiv.classList.add('hidden');
    
    try {
        log('Calling all AWS APIs...', 'info');
        const apiCalls = {
            iam: fetch('http://127.0.0.1:5001/api/run-iam-audit', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(payload) }),
            accessAnalyzer: fetch('http://127.0.0.1:5001/api/run-access-analyzer-audit', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(payload) }),
            securityhub: fetch('http://127.0.0.1:5001/api/run-securityhub-audit', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(payload) }),
            exposure: fetch('http://127.0.0.1:5001/api/run-exposure-audit', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(payload) }),
            guardduty: fetch('http://127.0.0.1:5001/api/run-guardduty-audit', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(payload) }),
            waf: fetch('http://127.0.0.1:5001/api/run-waf-audit', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(payload) }),
            cloudtrail: fetch('http://127.0.0.1:5001/api/run-cloudtrail-audit', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(payload) }),
            cloudwatch: fetch('http://127.0.0.1:5001/api/run-cloudwatch-audit', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(payload) }),
            inspector: fetch('http://127.0.0.1:5001/api/run-inspector-audit', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(payload) }),
            acm: fetch('http://127.0.0.1:5001/api/run-acm-audit', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(payload) }),
            compute: fetch('http://127.0.0.1:5001/api/run-compute-audit', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(payload) }),
            ecr: fetch('http://127.0.0.1:5001/api/run-ecr-audit', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(payload) }),
            databases: fetch('http://127.0.0.1:5001/api/run-databases-audit', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(payload) }),
            network_policies: fetch('http://127.0.0.1:5001/api/run-network-policies-audit', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(payload) }),
            federation: fetch('http://127.0.0.1:5001/api/run-federation-audit', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(payload) }),
            config_sh_status: fetch('http://127.0.0.1:5001/api/run-config-sh-status-audit', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(payload) }),
            kms: fetch('http://127.0.0.1:5001/api/run-kms-audit', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(payload) }),
            secrets_manager: fetch('http://127.0.0.1:5001/api/run-secrets-manager-audit', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(payload) }),
            connectivity: fetch('http://127.0.0.1:5001/api/run-connectivity-audit', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(payload) }),
            codepipeline: fetch('http://127.0.0.1:5001/api/run-codepipeline-audit', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(payload) })
        };
        
        const promises = Object.entries(apiCalls).map(async ([key, promise]) => {
            try { 
                const response = await promise; 
                if (!response.ok) { 
                    const errorData = await response.json(); 
                    throw new Error(errorData.error || `HTTP error! status: ${response.status}`); 
                } 
                return [key, await response.json()]; 
            } catch (error) { 
                log(`Error for API '${key}': ${error.message}`, 'error'); 
                return [key, null]; 
            }
        });

        const resolvedPromises = await Promise.all(promises);
        const results = Object.fromEntries(resolvedPromises);

        window.iamApiData = results.iam; 
        window.accessAnalyzerApiData = results.accessAnalyzer; 
        window.securityHubApiData = results.securityhub; 
        window.exposureApiData = results.exposure; 
        window.guarddutyApiData = results.guardduty; 
        window.wafApiData = results.waf; 
        window.cloudtrailApiData = results.cloudtrail; 
        window.cloudwatchApiData = results.cloudwatch; 
        window.inspectorApiData = results.inspector; 
        window.acmApiData = results.acm; 
        window.computeApiData = results.compute;
        window.ecrApiData = results.ecr;
        window.databasesApiData = results.databases; 
        window.networkPoliciesApiData = results.network_policies; 
        window.federationApiData = results.federation;
        window.configSHStatusApiData = results.config_sh_status; 
        window.kmsApiData = results.kms; 
        window.secretsManagerApiData = results.secrets_manager;
        window.connectivityApiData = results.connectivity;
        window.codepipelineApiData = results.codepipeline;
        
        console.log('=== CODEPIPELINE ASSIGNMENT DEBUG ===');
        console.log('results.codepipeline:', results.codepipeline);
        console.log('window.codepipelineApiData after assignment:', window.codepipelineApiData);
        console.log('Has pipelines:', window.codepipelineApiData?.results?.pipelines?.length);
        console.log('=====================================');


        
        if (!window.iamApiData || !window.networkPoliciesApiData) { 
            throw new Error("One or more critical API calls failed. Cannot continue."); 
        }
        
        window.allAvailableRegions = window.networkPoliciesApiData?.results?.all_regions || [];
        log('All data has been received.', 'success');
        
        buildAndRenderAllViews();
        await runAndDisplayHealthyStatus();

        // INICIA LA CORRECCIÓN
        log('Activating the Identity & Access view post-scan...', 'info');

        // Ocultar todas las vistas
        document.querySelectorAll('.view').forEach(v => v.classList.add('hidden'));
        
        // Mostrar la vista de IAM
        const iamViewToShow = document.getElementById('iam-view');
        if (iamViewToShow) {
            iamViewToShow.classList.remove('hidden');
        }

        // Actualizar el estilo "activo" en la barra lateral
        const sidebarLinks = document.querySelectorAll('#sidebar-nav a.main-nav-link');
        sidebarLinks.forEach(link => {
            link.classList.remove('bg-[#eb3496]');
            link.classList.add('hover:bg-[#1a335a]');
        });
        const activeIamLink = document.querySelector('#sidebar-nav a[data-view="iam"]');
        if (activeIamLink) {
            activeIamLink.classList.add('bg-[#eb3496]');
            activeIamLink.classList.remove('hover:bg-[#1a335a]');
        }
        // TERMINA LA CORRECCIÓN
    } catch (error) {
        const errorMsg = `Error: ${error.message || 'An unknown error occurred.'}`;
        console.error('Detailed Error:', error);
        errorMessageDiv.textContent = errorMsg;
        errorMessageDiv.classList.remove('hidden');
        log(`${errorMsg}`, 'error');
    } finally {
        runAnalysisBtn.disabled = false;
        loadingSpinner.classList.add('hidden');
        buttonText.textContent = 'Scan Account';
    }
};


const buildAndRenderAllViews = () => {
    try {
        log('Rendering all views…', 'info');
        buildHealthyStatusView();
        buildGeminiReportView();
        buildIamView();
        buildExposureView();
        buildGuarddutyView();
        buildWafView();
        buildCloudtrailView();
        buildCloudwatchView();
        buildInspectorView();
        buildAcmView();
        buildComputeView();
        buildEcrView();
        buildDatabasesView();
        buildNetworkPoliciesView();
        buildConfigSHView();
        buildCodePipelineView();
        buildPlaygroundView();
        buildKmsSecretsView();
        buildConnectivityView();
        log('Views rendered.', 'success');
    } catch (e) { log(`Error rendering: ${e.message}`, 'error'); console.error(e); }
};

const createInitialEmptyState = () => `<div class="text-center py-16 bg-white rounded-lg">
    <svg xmlns="http://www.w3.org/2000/svg" fill="currentColor" class="mx-auto h-12 w-12 text-gray-400" viewBox="0 0 16 16">
        <path d="M8 16c3.314 0 6-2 6-5.5 0-1.5-.5-4-2.5-6 .25 1.5-1.25 2-1.25 2C11 4 9 .5 6 0c.357 2 .5 4-2 6-1.25 1-2 2.729-2 4.5C2 14 4.686 16 8 16m0-1c-1.657 0-3-1-3-2.75 0-.75.25-2 1.25-3C6.125 10 7 10.5 7 10.5c-.375-1.25.5-3.25 2-3.5-.179 1-.25 2 1 3 .625.5 1 1.364 1 2.25C11 14 9.657 15 8 15"/>
    </svg>
    <h3 class="mt-2 text-lg font-medium text-[#204071]">Welcome to AudiThor</h3>
    <p class="mt-1 text-sm text-gray-500">Enter your credentials and click "Scan Account"</p>
</div>`;




const exportResultsToJson = () => {
    if (!window.iamApiData) {
        alert("Aviso: Debes ejecutar un análisis primero antes de exportar los resultados.");
        return;
    }

    let scanType = "fast";
    if (window.configSHApiData || (window.inspectorApiData && window.inspectorApiData.results.findings && window.inspectorApiData.results.findings.length > 0)) {
        scanType = "deep";
    }
    
    const accountId = window.iamApiData.metadata.accountId;
    const accountAlias = window.federationApiData?.results?.iam_federation?.account_alias || "NoAlias";
    const timestamp = window.iamApiData.metadata.executionDate;

    const exportData = {
        metadata: {
            accountId: accountId,
            accountAlias: accountAlias,
            analysisTimestamp: timestamp,
            analysisType: scanType,
            exportTimestamp: new Date().toISOString()
        },
        results: {
            iam: window.iamApiData?.results || null,
            federation: window.federationApiData?.results || null,
            accessAnalyzer: window.accessAnalyzerApiData?.results || null,
            securityhub: window.securityHubApiData?.results || null,
            exposure: window.exposureApiData?.results || null,
            guardduty: window.guarddutyApiData?.results || null,
            waf: window.wafApiData?.results || null,
            cloudtrail: window.cloudtrailApiData?.results || null,
            cloudwatch: window.cloudwatchApiData?.results || null,
            inspector: window.inspectorApiData?.results || null,
            acm: window.acmApiData?.results || null,
            compute: window.computeApiData?.results || null,
            ecr: window.ecrApiData?.results || null,
            databases: window.databasesApiData?.results || null,
            networkPolicies: window.networkPoliciesApiData?.results || null,
            configAndSecurityHubStatus: window.configSHStatusApiData?.results || null,
            configAndSecurityHubDeepScan: window.configSHApiData?.results || null,
            kms: window.kmsApiData?.results || null,
            secretsManager: window.secretsManagerApiData?.results || null,
            playground: {
                traceroute: window.playgroundApiData?.results || null,
                sslscan: window.playgroundApiData?.sslscan || null
            },
            connectivity: window.connectivityApiData?.results || null,
            codepipeline: window.codepipelineApiData?.results || null,
            // MODIFICACIÓN: Incluir datos completos de TrailAlerts
            trailAlerts: window.trailAlertsData || null,
            audiThorScopeData: window.scopedResources,
            audiThorAuditorNotes: window.auditorNotes || []
        }
    };
    
    const filename = `${accountId}_${accountAlias}_${scanType}.json`;
    const jsonString = JSON.stringify(exportData, null, 2);
    const blob = new Blob([jsonString], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    
    document.body.removeChild(a);
    URL.revokeObjectURL(url);

    log(`Results successfully exported to the file: ${filename}`, 'success');
};


const handleJsonImport = (event) => {
    const file = event.target.files[0];
    if (!file) {
        log('No file selected.', 'info');
        return;
    }

    log(`Loading file: ${file.name}...`, 'info');
    const reader = new FileReader();

    reader.onload = (e) => {
        try {
            const importedData = JSON.parse(e.target.result);

            if (!importedData.metadata || !importedData.results) {
                throw new Error("The JSON file does not have the expected structure. (metadata/results).");
            }

            log(`JSON file parsed successfully. Account: ${importedData.metadata.accountId}`, 'info');

            const results = importedData.results;
            const metadata = { accountId: importedData.metadata.accountId, executionDate: importedData.metadata.analysisTimestamp };

            // Asignar todos los datos globales
            window.iamApiData = results.iam ? { metadata: metadata, results: results.iam } : null;
            window.federationApiData = results.federation ? { metadata: metadata, results: results.federation } : null;
            window.accessAnalyzerApiData = results.accessAnalyzer ? { metadata: metadata, results: results.accessAnalyzer } : null;
            window.securityHubApiData = results.securityhub ? { metadata: metadata, results: results.securityhub } : null;
            window.exposureApiData = results.exposure ? { metadata: metadata, results: results.exposure } : null;
            window.guarddutyApiData = results.guardduty ? { metadata: metadata, results: results.guardduty } : null;
            window.wafApiData = results.waf ? { metadata: metadata, results: results.waf } : null;
            window.cloudtrailApiData = results.cloudtrail ? { metadata: metadata, results: results.cloudtrail } : null;
            window.cloudwatchApiData = results.cloudwatch ? { metadata: metadata, results: results.cloudwatch } : null;
            window.inspectorApiData = results.inspector ? { metadata: metadata, results: results.inspector } : null;
            window.acmApiData = results.acm ? { metadata: metadata, results: results.acm } : null;
            window.computeApiData = results.compute ? { metadata: metadata, results: results.compute } : null;
            window.ecrApiData = results.ecr ? { metadata: metadata, results: results.ecr } : null;
            window.databasesApiData = results.databases ? { metadata: metadata, results: results.databases } : null;
            window.networkPoliciesApiData = results.networkPolicies ? { metadata: metadata, results: results.networkPolicies } : null;
            window.configSHStatusApiData = results.configAndSecurityHubStatus ? { metadata: metadata, results: results.configAndSecurityHubStatus } : null;
            window.configSHApiData = results.configAndSecurityHubDeepScan ? { metadata: metadata, results: results.configAndSecurityHubDeepScan } : null;
            window.kmsApiData = results.kms ? { metadata: metadata, results: results.kms } : null;
            window.secretsManagerApiData = results.secretsManager ? { metadata: metadata, results: results.secretsManager } : null;
            window.connectivityApiData = results.connectivity ? { metadata: metadata, results: results.connectivity } : null;
            window.codepipelineApiData = results.codepipeline ? { metadata: metadata, results: results.codepipeline } : null;
            



            const playgroundImportData = results.playground || {};
            window.playgroundApiData = {
                metadata: metadata,
                results: playgroundImportData.traceroute || null,
                sslscan: playgroundImportData.sslscan || null
            };
            
            // Importar datos completos de TrailAlerts
            window.trailAlertsData = results.trailAlerts || null;
            
            // Log sobre TrailAlerts solo una vez aquí
            if (window.trailAlertsData) {
                const alertsCount = window.trailAlertsData.results?.alerts?.length || 0;
                log(`Imported TrailAlerts data with ${alertsCount} security alerts`, 'success');
            }

            window.allAvailableRegions = window.networkPoliciesApiData?.results?.all_regions || [];

            log('Data imported into the application state.', 'success');
            
            if (results.audiThorScopeData) {
                window.scopedResources = results.audiThorScopeData;
                saveScopedResources(); // Guardarlo en localStorage
                log(`Importados ${Object.keys(window.scopedResources).length} recursos marcados.`, 'success');
            } else {
                window.scopedResources = {}; // Limpiar si el fichero no tiene datos de scope
                saveScopedResources();
            }

            if (results.audiThorAuditorNotes) {
                // Solo carga las notas si existen en el fichero importado.
                window.auditorNotes = results.audiThorAuditorNotes;
                saveAuditorNotes(); 
                log(`Importadas ${window.auditorNotes.length} notas del auditor desde el fichero.`, 'success');
            } else {
                // Si el fichero no tiene notas, LIMPIAR las actuales en lugar de mantenerlas
                window.auditorNotes = [];
                saveAuditorNotes();
                log('Notas del auditor limpiadas al importar nuevo cliente.', 'info');
            }



            // 1. Construir el contenido de todas las vistas en segundo plano
            // NOTA: buildCloudtrailView() ya se ejecuta aquí y manejará los datos de TrailAlerts automáticamente
            buildAndRenderAllViews();
            
            // 2. Ejecutar lógicas adicionales que puedan ser necesarias
            runAndDisplayHealthyStatus();

            // 3. ELIMINADO: Ya no necesitamos llamar buildCloudtrailView() por segunda vez
            // porque ya se ejecuta en buildAndRenderAllViews() y manejará los datos importados

            // 4. Asegurarse de que se muestra la vista correcta
            log('Activating the Identity & Access view post-import...', 'info');

            // Ocultar todas las vistas
            document.querySelectorAll('.view').forEach(v => v.classList.add('hidden'));
            
            // Mostrar la vista de IAM
            const iamViewToShow = document.getElementById('iam-view');
            if (iamViewToShow) {
                iamViewToShow.classList.remove('hidden');
            }

            // Actualizar el estilo "activo" en la barra lateral para que sea coherente
            const sidebarLinks = document.querySelectorAll('#sidebar-nav a.main-nav-link');
            sidebarLinks.forEach(link => {
                link.classList.remove('bg-[#eb3496]');
                link.classList.add('hover:bg-[#1a335a]');
            });
            const activeIamLink = document.querySelector('#sidebar-nav a[data-view="iam"]');
            if (activeIamLink) {
                activeIamLink.classList.add('bg-[#eb3496]');
                activeIamLink.classList.remove('hover:bg-[#1a335a]');
            }

        } catch (error) {
            log(`Error importing the JSON file: ${error.message}`, 'error');
            console.error(error);
            errorMessageDiv.textContent = 'Error: El fichero seleccionado no es un JSON válido o tiene un formato incorrecto.';
            errorMessageDiv.classList.remove('hidden');
        }
    };

    reader.onerror = () => {
        log('Error reading the file.', 'error');
        errorMessageDiv.textContent = 'Error: No se pudo leer el fichero seleccionado.';
        errorMessageDiv.classList.remove('hidden');
    };

    reader.readAsText(file);
    event.target.value = '';
};



const displayHealthyStatus = (selectedRegion) => {
    // Placeholder - necesitarías implementar esta función
    log('Displaying healthy status...', 'info');
};

const runAndDisplayHealthyStatus = async () => {
    if (!window.iamApiData) {
        log('No audit data available for healthy status analysis.', 'info');
        return;
    }

    log('Running healthy status analysis...', 'info');
    
    try {
        // Prepare audit data structure
        const auditData = {
            iam: window.iamApiData,
            federation: window.federationApiData,
            accessAnalyzer: window.accessAnalyzerApiData,
            securityhub: window.securityHubApiData,
            exposure: window.exposureApiData,
            guardduty: window.guarddutyApiData,
            waf: window.wafApiData,
            cloudtrail: window.cloudtrailApiData,
            cloudwatch: window.cloudwatchApiData,
            inspector: window.inspectorApiData,
            acm: window.acmApiData,
            compute: window.computeApiData,
            ecr: window.ecrApiData,
            databases: window.databasesApiData,
            networkPolicies: window.networkPoliciesApiData,
            configSH: window.configSHApiData,
            configSHStatus: window.configSHStatusApiData,
            config_sh: window.configSHStatusApiData,
            kms: window.kmsApiData,
            secretsManager: window.secretsManagerApiData,
            connectivity: window.connectivityApiData,
            codepipeline: window.codepipelineApiData
        };

        // Call the backend API to check rules
        const response = await fetch('http://127.0.0.1:5001/api/check-healthy-status-rules', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify(auditData)
        });

        if (!response.ok) {
            throw new Error(`HTTP error! status: ${response.status}`);
        }

        const findings = await response.json();
        
        // Store findings globally
        window.lastHealthyStatusFindings = findings;
        
        log(`Healthy status analysis completed. Found ${findings.length} findings.`, 'success');
        
        // Import the functions dynamically to avoid circular imports
        const { renderHealthyStatusFindings, populateHealthyStatusFilter } = await import('/static/js/views/17_healthy_status.js');
        
        // Render the findings
        renderHealthyStatusFindings(findings);
        populateHealthyStatusFilter(findings);
        
        // Also populate the Gemini region filter
        populateGeminiRegionFilter(findings);
        
    } catch (error) {
        log(`Error in healthy status analysis: ${error.message}`, 'error');
        console.error('Healthy status error:', error);
    }
};

const populateHealthyStatusFilter = () => {
    // Placeholder - necesitarías implementar esta función
    log('Populating healthy status filters...', 'info');
};

const populateGeminiRegionFilter = (findings) => {
    const select = document.getElementById('gemini-region-filter');
    if (!select) return;

    const regions = new Set();
    regions.add('all');
    findings.forEach(finding => {
        finding.affected_resources.forEach(res => {
            if (res.region) {
                regions.add(res.region);
            }
        });
    });

    // Clear existing options except "All Regions"
    select.innerHTML = '<option value="all">All Regions</option>';
    
    const sortedRegions = Array.from(regions).sort();
    sortedRegions.forEach(region => {
        if (region !== 'all') {
            const option = document.createElement('option');
            option.value = region;
            option.textContent = region;
            select.appendChild(option);
        }
    });
};

// 5. PUNTO DE ENTRADA
document.addEventListener('DOMContentLoaded', () => {
    // Inicializar selectores
    views = document.querySelectorAll('.view');
    mainNavLinks = document.querySelectorAll('.main-nav-link');
    runAnalysisBtn = document.getElementById('run-analysis-button');
    accessKeyInput = document.getElementById('access-key-input');
    secretKeyInput = document.getElementById('secret-key-input');
    sessionTokenInput = document.getElementById('session-token-input');
    loadingSpinner = document.getElementById('loading-spinner');
    buttonText = document.getElementById('button-text');
    errorMessageDiv = document.getElementById('error-message');
    logContainer = document.getElementById('log-container');
    clearLogBtn = document.getElementById('clear-log-btn');
    toggleLogBtn = document.getElementById('toggle-log-btn');
    logPanel = document.getElementById('log-panel');
    loadScopedResources();
    loadAuditorNotes();

    // Cargar iconos de la barra lateral
    loadSidebarIcons();

    // Configurar navegación principal
    const sidebarNav = document.getElementById('sidebar-nav');
    if (sidebarNav) {
        sidebarNav.addEventListener('click', handleMainNavClick);
    }

    // Configurar botón de notas
    const openNotesButton = document.getElementById('open-notes-btn');
    if (openNotesButton) {
        openNotesButton.addEventListener('click', openNotesModal);
    }


    // Configurar botón de análisis
    if (runAnalysisBtn) {
        runAnalysisBtn.addEventListener('click', runAnalysisFromInputs);
    }

    // Configurar botones de importación/exportación
    const exportBtn = document.getElementById('export-results-button');
    const importBtn = document.getElementById('import-results-button');
    const fileInput = document.getElementById('json-file-input');

    if (exportBtn) {
        exportBtn.addEventListener('click', exportResultsToJson);
    }

    if (importBtn && fileInput) {
        importBtn.addEventListener('click', () => fileInput.click());
        fileInput.addEventListener('change', handleJsonImport);
    }

    // Configurar controles del log
    if (clearLogBtn) {
        clearLogBtn.addEventListener('click', () => {
            if (logContainer) {
                logContainer.innerHTML = '';
                // Remover la clase de nuevo log si existe
                if (logPanel) {
                    logPanel.classList.remove('new-log');
                }
            }
        });
    }

    if (toggleLogBtn && logPanel) {
        toggleLogBtn.addEventListener('click', (e) => {
            e.stopPropagation(); // Evitar que se propague al panel
            minimizeLogPanel();
        });

        // Click en el panel flotante para maximizar
        logPanel.addEventListener('click', (e) => {
            if (logPanel.classList.contains('floating')) {
                e.stopPropagation();
                maximizeLogPanel();
            }
        });
    }

    // 3. AÑADE estas dos funciones nuevas después de la sección anterior:

    // Función para minimizar el panel (convertir a flotante)
    function minimizeLogPanel() {
        if (logPanel) {
            logPanel.classList.remove('minimized');
            logPanel.classList.add('floating');
            
            if (toggleLogBtn) {
                toggleLogBtn.textContent = 'Show Log';
            }
            
            log('Event Log minimized to floating button', 'info');
        }
    }

    // Función para maximizar el panel (volver al estado normal)
    function maximizeLogPanel() {
        if (logPanel) {
            logPanel.classList.remove('floating', 'new-log');
            
            if (toggleLogBtn) {
                toggleLogBtn.textContent = 'Minimize';
            }
            
            log('Event Log expanded', 'info');
        }
    }

    // Configurar modal
    setupModalControls();

    // Inicializar vistas vacías
    views.forEach(view => {
        if (view.id !== 'iam-view') {
            view.innerHTML = createInitialEmptyState();
        }
    });

    // Mostrar vista inicial (iam)
    const initialView = document.getElementById('iam-view');
    if (initialView) {
        initialView.classList.remove('hidden');
        buildIamView();
    }

    log('Application initialized successfully.', 'success');
});

// 6. EXPOSICIÓN DE FUNCIONES GLOBALES
window.openModalWithSsoDetails = openModalWithSsoDetails;
window.openModalWithAccessKeyDetails = openModalWithAccessKeyDetails;
window.openModalWithUserGroups = openModalWithUserGroups;
window.openModalWithEc2Tags = openModalWithEc2Tags;
window.openModalWithLambdaTags = openModalWithLambdaTags;
window.openModalWithTlsDetails = openModalWithTlsDetails;
window.toggleAlarmDetails = toggleAlarmDetails;
window.showCloudtrailEventDetails = showCloudtrailEventDetails;
window.openModalWithKmsPolicy = openModalWithKmsPolicy;
window.openModalWithLambdaRole = openModalWithLambdaRole;
window.openModalWithEcrPolicy = openModalWithEcrPolicy;
window.copyToClipboard = copyToClipboard;
window.buildCodePipelineView = buildCodePipelineView;
window.openModalWithUserRoles = openModalWithUserRoles;
window.openModalWithSecretDetails = openModalWithSecretDetails;
window.openScopeModal = openScopeModal;