/**
 * app.js
 * Fichero principal (el "cerebro") de la lógica de la aplicación AudiThor.
 */

// 0. HELPERS/API (lee CONSTANTS de window)
const _CONST = window.CONSTANTS || {};
const API = _CONST.API || {};
const TIMERS = _CONST.TIMERS || { BULK_POLL_INTERVAL_MS: 2000, BULK_TIMEOUT_MIN: 45 };

const requireApi = (path, fallbackMsg) => {
    const v = path;
    if (!v) {
        const msg = fallbackMsg || 'Backend API base is not configured. Set window.BACKEND_BASE before loading constants.js.';
        throw new Error(msg);
    }
    return v;
};

// ---- FETCH con backoff para 502/503/504 ----
async function fetchWithBackoff(url, opts = {}, {
  attempts = 5,
  baseDelayMs = 500,
  backoffFactor = 2,
  retryStatuses = [502, 503, 504]
} = {}) {
  let lastErr;
  for (let i = 0; i < attempts; i++) {
    try {
      const res = await fetch(url, opts);
      if (res.ok || !retryStatuses.includes(res.status)) {
        return res;
      }
      // Estado 5xx transitorio: esperar y reintentar
      const bodyPreview = await res.text().catch(() => '');
      lastErr = new Error(`HTTP ${res.status}${bodyPreview ? ` - ${bodyPreview.slice(0, 500)}` : ''}`);
    } catch (e) {
      lastErr = e;
    }
    // backoff exponencial: 500ms, 1s, 2s, 4s...
    const delay = baseDelayMs * Math.pow(backoffFactor, i);
    await new Promise(r => setTimeout(r, delay));
  }
  throw lastErr || new Error('fetchWithBackoff: unknown error');
}

// 1. IMPORTACIONES
import { refreshHealthyStatus } from './views/17_healthy_status.js';

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
import { buildNetworkPoliciesView, openModalWithVpcTags } from '/static/js/views/13_network_policies.js';
import { buildConnectivityView } from '/static/js/views/14_connectivity.js';
import { buildConfigSHView } from '/static/js/views/15_config_sh.js';
import { buildCodePipelineView } from '/static/js/views/18_codepipeline.js';
import { buildPlaygroundView } from '/static/js/views/16_playground.js';
import { buildHealthyStatusView, buildGeminiReportView, buildScopedInventoryView, buildAuditorNotesView } from '/static/js/views/17_healthy_status.js';

// Importar funciones para onclick
import { openModalWithTlsDetails } from '/static/js/views/02_exposure.js';
import { openModalWithEcrPolicy } from '/static/js/views/04_ecr.js';
import { openModalWithKmsPolicy, openModalWithSecretDetails } from '/static/js/views/12_kms_secrets.js';
import { showCloudtrailEventDetails } from '/static/js/views/06_cloudtrail.js';
import { toggleAlarmDetails } from '/static/js/views/07_cloudwatch.js';
import { openModalWithEc2Tags, openModalWithLambdaTags, openModalWithLambdaRole } from '/static/js/views/10_compute.js';

// Importar iconos
import { SIDEBAR_ICONS } from '/static/js/icons.js';

// Auth helpers (oidc-client-ts)
import { getUser, login, logout, onAuthChange } from '/static/js/auth.js';

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
window.secretsManagerApiData = null;
window.allAvailableRegions = [];
window.lastCloudtrailLookupResults = [];
window.lastHealthyStatusFindings = [];
window.trailAlertsData = null;
window.scopedResources = {};
window.auditorNotes = [];

// 3. SELECTORES
let views, mainNavLinks, runAnalysisBtn, accessKeyInput, secretKeyInput, sessionTokenInput, loadingSpinner, buttonText, errorMessageDiv, logContainer, clearLogBtn, toggleLogBtn, logPanel;

// === NUEVO: Mapa de builders por clave de vista ===
const VIEW_BUILDERS = {
  'iam': buildIamView,
  'exposure': buildExposureView,
  'guardduty': buildGuarddutyView,
  'waf': buildWafView,
  'cloudtrail': buildCloudtrailView,
  'cloudwatch': buildCloudwatchView,
  'inspector': buildInspectorView,
  'acm': buildAcmView,
  'compute': buildComputeView,
  'ecr': buildEcrView,
  'databases': buildDatabasesView,
  'kms-secrets': buildKmsSecretsView,
  'network-policies': buildNetworkPoliciesView,
  'connectivity': buildConnectivityView,
  'config-sh': buildConfigSHView,
  'codepipeline': buildCodePipelineView,
  'playground': buildPlaygroundView,
  'healthy-status': () => { buildScopedInventoryView(); buildAuditorNotesView(); }
};

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
                span.innerHTML = '';
                const iconDiv = document.createElement('div');
                iconDiv.innerHTML = SIDEBAR_ICONS[iconKey];
                iconDiv.className = 'flex-shrink-0';
                const textDiv = document.createElement('div');
                textDiv.textContent = currentText;
                textDiv.className = 'ml-3';
                span.appendChild(iconDiv);
                span.appendChild(textDiv);
                span.className = 'flex items-center';
            }
        }
    });
};

// --- GESTIÓN DE SCOPE ---
const SCOPE_STORAGE_KEY = 'audiThorScopedResources';
const loadScopedResources = () => {
    const stored = localStorage.getItem(SCOPE_STORAGE_KEY);
    window.scopedResources = stored ? JSON.parse(stored) : {};
    log(`${Object.keys(window.scopedResources).length} recursos marcados cargados desde localStorage.`, 'info');
};
const saveScopedResources = () => localStorage.setItem(SCOPE_STORAGE_KEY, JSON.stringify(window.scopedResources));
const setResourceScope = (arn, comment = '') => {
  if (!arn) return;
  window.scopedResources[arn] = { comment: comment ?? '' };
  log(`Recurso ${arn} marcado como 'in scope'.`, 'success');
  saveScopedResources();
  rerenderCurrentView();
};
const removeResourceScope = (arn) => {
    console.log('%c[LOG DESDE app.js] -> Se ha llamado a la función GLOBAL removeResourceScope.', 'color: green; font-weight: bold;');
    console.group(`[APP] Attempting to remove scope for ARN: ${arn}`);
    if (arn && window.scopedResources[arn]) {
        console.log('Before Deletion:', JSON.parse(JSON.stringify(window.scopedResources)));
        delete window.scopedResources[arn];
        console.log('After Deletion:', JSON.parse(JSON.stringify(window.scopedResources)));
        log(`Resource ${arn} unmarked.`, 'info');
        saveScopedResources();
        console.log('Now calling rerenderCurrentView() to update the UI...');
        rerenderCurrentView();
    } else {
        console.error('ARN not found in scopedResources. Nothing to remove.');
    }
    console.groupEnd();
};

// --- NOTAS DEL AUDITOR ---
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
const saveAuditorNotes = () => localStorage.setItem(NOTES_STORAGE_KEY, JSON.stringify(window.auditorNotes));
const saveOrUpdateNote = (noteId, noteContent, noteTitle, noteArn, noteControl, view, tab) => {
    if (noteId) {
        const i = window.auditorNotes.findIndex(n => n.id === noteId);
        if (i > -1) {
            Object.assign(window.auditorNotes[i], {
                title: noteTitle,
                content: noteContent,
                arn: noteArn,
                controlId: noteControl,
                lastModified: new Date().toISOString()
            });
            log(`Nota con ID ${noteId} actualizada.`, 'success');
        }
    } else {
        window.auditorNotes.push({
            id: Date.now(),
            view, tab,
            timestamp: new Date().toISOString(),
            title: noteTitle,
            arn: noteArn,
            controlId: noteControl,
            content: noteContent
        });
        log(`Nota nueva '${noteTitle}' guardada.`, 'success');
    }
    saveAuditorNotes();
    buildAuditorNotesView();
};

const openNotesModal = (noteId = null) => {
    const modal = document.getElementById('notes-modal');
    const titleHeader = document.getElementById('notes-modal-title');
    const textarea = document.getElementById('notes-modal-textarea');
    const saveBtn = document.getElementById('notes-modal-save-btn');
    const cancelBtn = document.getElementById('notes-modal-cancel-btn');
    const titleInput = document.getElementById('notes-modal-title-input');
    const arnInput = document.getElementById('notes-modal-arn-input');
    const controlInput = document.getElementById('notes-modal-control-input');

    let noteToEdit = null;

    if (noteId) {
        noteToEdit = window.auditorNotes.find(n => n.id === noteId);
        if (!noteToEdit) { log(`Error: No se encontró la nota con ID ${noteId}`, 'error'); return; }
        titleHeader.textContent = 'Edit Note';
        titleInput.value = noteToEdit.title;
        arnInput.value = noteToEdit.arn || '';
        controlInput.value = noteToEdit.controlId || '';
        textarea.value = noteToEdit.content;
    } else {
        const activeViewLink = document.querySelector('#sidebar-nav a.bg-\\[\\#eb3496\\]');
        const viewText = activeViewLink ? activeViewLink.querySelector('span div:last-child').textContent : 'General';
        titleHeader.textContent = `New Note for: ${viewText}`;
        textarea.value = ''; titleInput.value = ''; arnInput.value = ''; controlInput.value = '';
    }

    const handleSave = () => {
        const noteContent = textarea.value.trim();
        const noteTitle = titleInput.value.trim();
        const noteArn = arnInput.value.trim();
        const noteControl = controlInput.value.trim();
        const activeViewLink = document.querySelector('#sidebar-nav a.bg-\\[\\#eb3496\\]');
        const viewName = activeViewLink ? activeViewLink.dataset.view : 'unknown';
        if (noteContent && noteTitle) {
            saveOrUpdateNote(noteToEdit ? noteToEdit.id : null, noteContent, noteTitle, noteArn, noteControl, viewName, 'main');
            modal.classList.add('hidden');
        } else {
            alert('Por favor, introduce al menos un título y el contenido de la nota.');
        }
    };

    const newSaveBtn = saveBtn.cloneNode(true);
    saveBtn.parentNode.replaceChild(newSaveBtn, saveBtn);
    newSaveBtn.addEventListener('click', handleSave);

    cancelBtn.onclick = () => modal.classList.add('hidden');
    modal.classList.remove('hidden');
    titleInput.focus();
};
// Modal de scope (crear/editar el comentario del recurso)
const openScopeModal = (arn, currentComment = '') => {
  const modal = document.getElementById('scope-modal');
  const title = document.getElementById('scope-modal-title');
  const textarea = document.getElementById('scope-comment-textarea');
  const saveBtn = document.getElementById('scope-modal-save-btn');
  const unscopeBtn = document.getElementById('scope-modal-unscope-btn');
  const closeBtn = document.getElementById('scope-modal-close-btn');

  if (!modal) {
    console.warn('openScopeModal: no se encontró #scope-modal en el DOM');
    return;
  }

  // Título y texto inicial
  try {
    title.textContent = `Marcar Recurso: ${String(arn || '').split('/').pop()}`;
  } catch { title.textContent = 'Marcar recurso'; }
  textarea.value = decodeURIComponent(currentComment || '');

  // Reemplazar listeners para evitar duplicados
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
// REEMPLAZA COMPLETO
const rerenderCurrentView = () => {
  log('Rerendering view(s) to reflect state changes...', 'info');

  // 1) Vista activa
  const activeLink = document.querySelector('#sidebar-nav a.bg-\\[\\#eb3496\\]');
  if (!activeLink) {
    log('Could not find an active view to rerender.', 'warning');
    return;
  }

  const activeViewName = activeLink.dataset.view;
  log(`Active view identified: ${activeViewName}`, 'info');

  // 2) Refresco inteligente
  if (activeViewName === 'healthy-status') {
    log('In Healthy Status. Refreshing ONLY the scoped inventory tab.', 'info');
    try { buildScopedInventoryView(); } catch (e) { console.error(e); }
  } else {
    const renderFunction = VIEW_BUILDERS?.[activeViewName];
    if (typeof renderFunction === 'function') {
      log(`Calling full renderer for active view: '${activeViewName}'...`, 'info');

      // ✅ selector correcto del sub-tab activo dentro de la vista
      let activeSubTabKey = null;
      try {
        const sel = `#${activeViewName}-view .tab-link.border-\\[\\#eb3496\\]`;
        activeSubTabKey = document.querySelector(sel)?.dataset?.tab || null;
      } catch (err) {
        console.warn('Active sub-tab selector failed; continuing without restoring tab.', err);
      }

      try { renderFunction(); } catch (e) { console.error(e); }

      // Re-activar el mismo sub-tab si existía
      if (activeSubTabKey) {
        document
          .querySelector(`#${activeViewName}-view [data-tab="${activeSubTabKey}"]`)
          ?.click();
      }
    } else {
      log(`No renderer found for view '${activeViewName}'.`, 'warning');
    }
  }

  // 3) Refrescos en segundo plano (no tocan la vista actual)
  log('Performing background refresh of key views...', 'info');
  try {
    if (window.networkPoliciesApiData && activeViewName !== 'network-policies') buildNetworkPoliciesView();
    if (window.computeApiData && activeViewName !== 'compute') buildComputeView();
    if (window.databasesApiData && activeViewName !== 'databases') buildDatabasesView();
  } catch (e) {
    console.error('Background refresh error:', e);
  }
};

// === NUEVO: función común para mostrar vista y disparar builder ===
function showView(targetView) {
    if (!targetView) return;
    // activar en sidebar
    const links = document.querySelectorAll('#sidebar-nav a.main-nav-link');
    links.forEach(l => { l.classList.remove('bg-[#eb3496]'); l.classList.add('hover:bg-[#1a335a]'); });
    const link = document.querySelector(`#sidebar-nav a[data-view="${targetView}"]`);
    if (link) { link.classList.add('bg-[#eb3496]'); link.classList.remove('hover:bg-[#1a335a]'); }

    // mostrar contenedor
    document.querySelectorAll('.view').forEach(v => v.classList.add('hidden'));
    const targetViewElement = document.getElementById(`${targetView}-view`);
    if (targetViewElement) targetViewElement.classList.remove('hidden');

    // disparar builder específico
    const builder = VIEW_BUILDERS[targetView];
    if (builder) {
        try { builder(); } catch (e) { console.error('Error building view', targetView, e); log(`Error building '${targetView}': ${e.message}`, 'error'); }
    }
}

const handleMainNavClick = (e) => {
    e.preventDefault();
    const link = e.target.closest('a.main-nav-link');
    if (!link) return;
    const targetView = link.dataset.view;
    showView(targetView);
};

// ---------- AUTH UI SYNC ----------
function qs(id) { return document.getElementById(id); }

async function renderAuthUI() {
  const $login  = qs('login-btn') || document.querySelector('#sidebar-nav #login-btn');
  const $logout = qs('logout-btn') || document.querySelector('#sidebar-nav #logout-btn');
  const $who    = qs('auth-indicator') || document.querySelector('#sidebar-nav #auth-indicator');

  try {
    const user = await getUser();
    if (user && !user.expired) {
      const who = user.profile?.email || user.profile?.preferred_username || user.profile?.sub || 'Signed in';
      if ($who)   $who.textContent = who;
      if ($login) $login.classList.add('hidden');
      if ($logout) $logout.classList.remove('hidden');
      document.body.classList.add('is-auth');
    } else {
      if ($who)   $who.textContent = 'Not signed in';
      if ($login) $login.classList.remove('hidden');
      if ($logout) $logout.classList.add('hidden');
      document.body.classList.remove('is-auth');
    }
  } catch (e) {
    console.warn('renderAuthUI error:', e);
  }
}

// ===================================================================
// === BULK JOB HELPERS (asíncrono + polling con /api/scan/*) ========
// ===================================================================
const startBulkAudit = async (payload) => {
  const url = requireApi(API.BULK_RUN, 'Missing API.BULK_RUN');

  // Reintento con backoff para 502/503/504 + logging del cuerpo de error
  const res = await fetchWithBackoff(url, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload)
  });

  if (!res.ok) {
    const bodyTxt = await res.text().catch(() => '');
    throw new Error(`Bulk start failed: HTTP ${res.status}${bodyTxt ? ` - ${bodyTxt.slice(0, 500)}` : ''}`);
  }

  const data = await res.json().catch(() => ({}));
  if (!data?.job_id) throw new Error('Invalid response from bulk audit: missing job_id');

  const jobId = data.job_id;
  const pollUrl = requireApi(API.JOB_STATUS?.(jobId), 'Missing API.JOB_STATUS');
  const resultUrl = requireApi(API.JOB_RESULT?.(jobId), 'Missing API.JOB_RESULT');

  return { jobId, pollUrl, resultUrl };
};
  
  const pollJobUntilDone = async (
    { pollUrl, resultUrl },
    { intervalMs = TIMERS.BULK_POLL_INTERVAL_MS, maxMinutes = TIMERS.BULK_TIMEOUT_MIN } = {}
  ) => {
    const started = Date.now();
    let lastProgress = -1;
    let lastState = '';
  
    while (true) {
      if ((Date.now() - started) > maxMinutes * 60 * 1000) {
        throw new Error(`Timeout waiting for job to finish after ${maxMinutes} minutes`);
      }
  
      let res, data;
      try {
        res = await fetchWithBackoff(pollUrl, { method: 'GET' });
        if (!res.ok) throw new Error(`HTTP ${res.status}`);
        data = await res.json(); // { job_id, state, progress, error }
      } catch (err) {
        log(`Polling error (will retry): ${err.message}`, 'warning');
        await new Promise(r => setTimeout(r, intervalMs));
        continue;
      }
  
      const state = (data?.state || '').toLowerCase();
      const progress = Number.isFinite(data?.progress) ? data.progress : null;
  
      if (progress !== null && progress !== lastProgress) {
        lastProgress = progress;
        log(`Progress: ${progress}%`, 'info');
      }
      if (state && state !== lastState) {
        lastState = state;
        log(`Job state: ${state}`, state === 'error' ? 'error' : 'info');
      }
  
      if (state === 'error') {
        const errMsg = data?.error || 'Bulk job failed';
        throw new Error(errMsg);
      }
  
      if (state === 'done') {
        // pedir resultado final
        const rr = await fetchWithBackoff(resultUrl, { method: 'GET' });
        if (!rr.ok) {
          const bodyTxt = await rr.text().catch(() => '');
          throw new Error(`Error fetching job result: HTTP ${rr.status}${bodyTxt ? ` - ${bodyTxt.slice(0, 500)}` : ''}`);
        }
        const result = await rr.json();
        return result; // shape con todas las colecciones
      }
  
      await new Promise(r => setTimeout(r, intervalMs));
    }
  };
  // ===================================================================
  // === FIN BULK HELPERS ==============================================
  // ===================================================================
/**
 * runAnalysisFromInputs: intenta primero bulk (asíncrono).
 * Si falla, cae a modo legacy (paralelo), siempre usando CONSTANTS.API.
 */
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
    
    // Helper para asignar resultados a estado global desde bundle (bulk o legacy)
    const assignResultsIntoGlobals = (bundle) => {
        const root = bundle?.results ? bundle.results : bundle;

        const metaSource =
            bundle?.metadata ? bundle.metadata :
            root?.iam?.metadata || root?.networkPolicies?.metadata || root?.cloudtrail?.metadata || null;

        const wrap = (key) => root?.[key]
            ? (root[key]?.metadata && root[key]?.results ? root[key] : { metadata: metaSource || {}, results: root[key] })
            : null;

        window.iamApiData               = wrap('iam');
        window.federationApiData        = wrap('federation');
        window.accessAnalyzerApiData    = wrap('accessAnalyzer');
        window.securityHubApiData       = wrap('securityhub') || wrap('securityHub');
        window.exposureApiData          = wrap('exposure');
        window.guarddutyApiData         = wrap('guardduty');
        window.wafApiData               = wrap('waf');
        window.cloudtrailApiData        = wrap('cloudtrail');
        window.cloudwatchApiData        = wrap('cloudwatch');
        window.inspectorApiData         = wrap('inspector');
        window.acmApiData               = wrap('acm');
        window.computeApiData           = wrap('compute');
        window.ecrApiData               = wrap('ecr');
        window.databasesApiData         = wrap('databases');
        window.networkPoliciesApiData   = wrap('networkPolicies') || wrap('network_policies');
        window.connectivityApiData      = wrap('connectivity');
        window.configSHApiData          = wrap('configSHDeep') || wrap('config_sh_deep');
        window.configSHStatusApiData    = wrap('configSH') || wrap('config_sh') || wrap('configAndSecurityHubStatus');
        window.kmsApiData               = wrap('kms');
        window.secretsManagerApiData    = wrap('secretsManager');
        window.codepipelineApiData      = wrap('codepipeline');
        window.playgroundApiData        = root?.playground ? { metadata: metaSource || {}, results: root.playground?.traceroute || null, sslscan: root.playground?.sslscan || null } : null;
        window.trailAlertsData          = root?.trailAlerts || null;

        window.lastAwsAccountId         = window.iamApiData?.metadata?.accountId || metaSource?.accountId;
        window.regionsIncluded          = window.iamApiData?.metadata?.regions || [];
        window.allAvailableRegions      = window.networkPoliciesApiData?.results?.all_regions || window.networkPoliciesApiData?.results?.allRegions || [];
    };

    // === 1) INTENTAR BULK ===
    try {
        log('Trying async bulk mode…', 'info');
        const { jobId, pollUrl, resultUrl } = await startBulkAudit(payload);
        log(`Bulk job accepted. Job ID: ${jobId}`, 'success');
        const finalResults = await pollJobUntilDone({ pollUrl, resultUrl });
        log('Bulk job completed. Assigning results…', 'success');

        assignResultsIntoGlobals(finalResults);

    } catch (bulkErr) {
        log(`Bulk mode unavailable or failed (${bulkErr.message}). Falling back to legacy parallel calls…`, 'warning');

        // === 2) LEGACY (todas las URLs desde CONSTANTS.API) ===
        try {
            const R = requireApi(API.RUNS, 'Missing API.RUNS map');
            const apiCalls = {
                iam:                 fetch(R.iam,               { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(payload) }),
                accessAnalyzer:      fetch(R.accessAnalyzer,    { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(payload) }),
                securityhub:         fetch(R.securityhub,       { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(payload) }),
                exposure:            fetch(R.exposure,          { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(payload) }),
                guardduty:           fetch(R.guardduty,         { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(payload) }),
                waf:                 fetch(R.waf,               { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(payload) }),
                cloudtrail:          fetch(R.cloudtrail,        { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(payload) }),
                cloudwatch:          fetch(R.cloudwatch,        { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(payload) }),
                inspector:           fetch(R.inspector,         { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(payload) }),
                acm:                 fetch(R.acm,               { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(payload) }),
                compute:             fetch(R.compute,           { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(payload) }),
                ecr:                 fetch(R.ecr,               { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(payload) }),
                databases:           fetch(R.databases,         { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(payload) }),
                network_policies:    fetch(R.network_policies,  { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(payload) }),
                federation:          fetch(R.federation,        { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(payload) }),
                config_sh_status:    fetch(R.config_sh_status,  { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(payload) }),
                kms:                 fetch(R.kms,               { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(payload) }),
                secrets_manager:     fetch(R.secrets_manager,   { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(payload) }),
                connectivity:        fetch(R.connectivity,      { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(payload) }),
                codepipeline:        fetch(R.codepipeline,      { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(payload) })
            };
            
            const promises = Object.entries(apiCalls).map(async ([key, promise]) => {
                try { 
                    const response = await promise; 
                    if (!response.ok) { 
                        const errorData = await response.json().catch(()=>({}));
                        const msg = errorData?.error ? `HTTP ${response.status} - ${errorData.error}` : `HTTP error! status: ${response.status}`;
                        throw new Error(msg); 
                    } 
                    return [key, await response.json()]; 
                } catch (error) { 
                    log(`Error for API '${key}': ${error.message}`, 'error'); 
                    return [key, null]; 
                }
            });

            const resolvedPromises = await Promise.all(promises);
            const results = Object.fromEntries(resolvedPromises);

            const bundle = {
                results: {
                    iam: results.iam,
                    federation: results.federation,
                    accessAnalyzer: results.accessAnalyzer,
                    securityhub: results.securityhub,
                    exposure: results.exposure,
                    guardduty: results.guardduty,
                    waf: results.waf,
                    cloudtrail: results.cloudtrail,
                    cloudwatch: results.cloudwatch,
                    inspector: results.inspector,
                    acm: results.acm,
                    compute: results.compute,
                    ecr: results.ecr,
                    databases: results.databases,
                    networkPolicies: results.network_policies,
                    configSH: results.config_sh_status,
                    kms: results.kms,
                    secretsManager: results.secrets_manager,
                    connectivity: results.connectivity,
                    codepipeline: results.codepipeline
                }
            };

            assignResultsIntoGlobals(bundle);

        } catch (legacyErr) {
            const errorMsg = `Error (legacy mode): ${legacyErr.message || 'Unknown error'}`;
            console.error('Detailed Error:', legacyErr);
            errorMessageDiv.textContent = errorMsg;
            errorMessageDiv.classList.remove('hidden');
            log(errorMsg, 'error');
            runAnalysisBtn.disabled = false;
            loadingSpinner.classList.add('hidden');
            buttonText.textContent = 'Scan Account';
            return;
        }
    }

    // Post-proceso común
    try {
        log('All data has been received.', 'success');
        buildAndRenderAllViews();
        await runAndDisplayHealthyStatus();

        // Mostrar IAM y marcar activo en sidebar
        log('Activating the Identity & Access view post-scan...', 'info');
        showView('iam');
    } catch (error) {
        const errorMsg = `Render error: ${error.message || 'Unknown'}`;
        console.error(error);
        errorMessageDiv.textContent = errorMsg;
        errorMessageDiv.classList.remove('hidden');
        log(errorMsg, 'error');
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

// EXPORT/IMPORT
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
            accountId,
            accountAlias,
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
    a.href = url; a.download = filename;
    document.body.appendChild(a); a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);

    log(`Results successfully exported to the file: ${filename}`, 'success');
};

const handleJsonImport = (event) => {
    const file = event.target.files[0];
    if (!file) { log('No file selected.', 'info'); return; }

    log(`Loading file: ${file.name}...`, 'info');
    const reader = new FileReader();

    reader.onload = (e) => {
        try {
            console.log("%cAPP.JS [Paso 1]: Fichero JSON leído y parseado correctamente.", "color: blue; font-weight: bold;");
            const importedData = JSON.parse(e.target.result);
            if (!importedData.metadata || !importedData.results) throw new Error("The JSON file does not have the expected structure. (metadata/results).");

            log(`JSON file parsed successfully. Account: ${importedData.metadata.accountId}`, 'info');

            const results = importedData.results;
            const metadata = { accountId: importedData.metadata.accountId, executionDate: importedData.metadata.analysisTimestamp };

            window.iamApiData = results.iam ? { metadata, results: results.iam } : null;
            window.federationApiData = results.federation ? { metadata, results: results.federation } : null;
            window.accessAnalyzerApiData = results.accessAnalyzer ? { metadata, results: results.accessAnalyzer } : null;
            window.securityHubApiData = results.securityhub ? { metadata, results: results.securityhub } : null;
            window.exposureApiData = results.exposure ? { metadata, results: results.exposure } : null;
            window.guarddutyApiData = results.guardduty ? { metadata, results: results.guardduty } : null;
            window.wafApiData = results.waf ? { metadata, results: results.waf } : null;
            window.cloudtrailApiData = results.cloudtrail ? { metadata, results: results.cloudtrail } : null;
            window.cloudwatchApiData = results.cloudwatch ? { metadata, results: results.cloudwatch } : null;
            window.inspectorApiData = results.inspector ? { metadata, results: results.inspector } : null;
            window.acmApiData = results.acm ? { metadata, results: results.acm } : null;
            window.computeApiData = results.compute ? { metadata, results: results.compute } : null;
            window.ecrApiData = results.ecr ? { metadata, results: results.ecr } : null;
            window.databasesApiData = results.databases ? { metadata, results: results.databases } : null;
            window.networkPoliciesApiData = results.networkPolicies ? { metadata, results: results.networkPolicies } : null;
            window.configSHStatusApiData = results.configAndSecurityHubStatus ? { metadata, results: results.configAndSecurityHubStatus } : null;
            window.configSHApiData = results.configAndSecurityHubDeepScan ? { metadata, results: results.configAndSecurityHubDeepScan } : null;
            window.kmsApiData = results.kms ? { metadata, results: results.kms } : null;
            window.secretsManagerApiData = results.secretsManager ? { metadata, results: results.secretsManager } : null;
            window.connectivityApiData = results.connectivity ? { metadata, results: results.connectivity } : null;
            window.codepipelineApiData = results.codepipeline ? { metadata, results: results.codepipeline } : null;

            const playgroundImportData = results.playground || {};
            window.playgroundApiData = { metadata, results: playgroundImportData.traceroute || null, sslscan: playgroundImportData.sslscan || null };
            
            window.trailAlertsData = results.trailAlerts || null;
            if (window.trailAlertsData) {
                const alertsCount = window.trailAlertsData.results?.alerts?.length || 0;
                log(`Imported TrailAlerts data with ${alertsCount} security alerts`, 'success');
            }

            window.allAvailableRegions = window.networkPoliciesApiData?.results?.all_regions || [];

            log('Data imported into the application state.', 'success');
            
            if (results.audiThorScopeData) {
                window.scopedResources = results.audiThorScopeData;
                saveScopedResources();
                log(`Importados ${Object.keys(window.scopedResources).length} recursos marcados.`, 'success');
            } else {
                window.scopedResources = {};
                saveScopedResources();
            }

            if (results.audiThorAuditorNotes) {
                window.auditorNotes = results.audiThorAuditorNotes;
                saveAuditorNotes(); 
                log(`Importadas ${window.auditorNotes.length} notas del auditor desde el fichero.`, 'success');
            } else {
                window.auditorNotes = [];
                saveAuditorNotes();
                log('Notas del auditor limpiadas al importar nuevo cliente.', 'info');
            }

            buildAndRenderAllViews();
            console.log("%cAPP.JS [Paso 2]: Llamando a runAndDisplayHealthyStatus()... La ejecución NO esperará.", "color: orange; font-weight: bold;");
            runAndDisplayHealthyStatus();
            console.log("%cAPP.JS [Paso 4]: La ejecución continuó INMEDIATAMENTE después de llamar a runAndDisplayHealthyStatus.", "color: red; font-weight: bold;");

            log('Activating the Identity & Access view post-import...', 'info');
            showView('iam');

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

// HEALTHY STATUS
const displayHealthyStatus = (selectedRegion) => { log('Displaying healthy status...', 'info'); };

const runAndDisplayHealthyStatus = async () => {
    if (!window.iamApiData) { log('No audit data available for healthy status analysis.', 'info'); return; }
    log('Running healthy status analysis...', 'info');
    try {
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

        const url = requireApi(API.HEALTHY_STATUS, 'Missing API.HEALTHY_STATUS');
        const response = await fetch(url, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(auditData)
        });

        if (!response.ok) throw new Error(`HTTP error! status: ${response.status}`);

        const findings = await response.json();
        window.lastHealthyStatusFindings = findings;
        console.log("%cAPP.JS [Paso 3]: ¡DATOS RECIBIDOS! runAndDisplayHealthyStatus() ha terminado. 'window.lastHealthyStatusFindings' ahora tiene " + window.lastHealthyStatusFindings.length + " elementos.", "color: green; font-weight: bold;");
        
        log(`Healthy status analysis completed. Found ${findings.length} findings.`, 'success');
        
        refreshHealthyStatus(findings);      // ← resetea filtros + render inmediato
        populateGeminiRegionFilter(findings);
        
    } catch (error) {
        log(`Error in healthy status analysis: ${error.message}`, 'error');
        console.error('Healthy status error:', error);
    }
};

const populateHealthyStatusFilter = () => { log('Populating healthy status filters...', 'info'); };

const populateGeminiRegionFilter = (findings) => {
    const select = document.getElementById('gemini-region-filter');
    if (!select) return;
    const regions = new Set();
    regions.add('all');
    findings.forEach(finding => {
        finding.affected_resources.forEach(res => { if (res.region) regions.add(res.region); });
    });
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

// NOTAS: detalles y borrado
const showNoteDetails = (noteId) => {
    const modal = document.getElementById('note-details-modal');
    const titleEl = document.getElementById('note-details-title');
    const contentEl = document.getElementById('note-details-content');
    const closeBtn = document.getElementById('note-details-close-btn');
    const editBtn = document.getElementById('note-details-edit-btn');
    const deleteBtn = document.getElementById('note-details-delete-btn');

    const note = window.auditorNotes.find(n => n.id === noteId);
    if (!note) return;

    titleEl.textContent = note.title;

    let arnHtml = note.arn ? `
        <div class="mt-2">
            <p class="font-semibold text-gray-700">Recurso Asociado:</p>
            <code class="text-xs text-gray-800 bg-gray-100 p-2 rounded-md block break-all">${note.arn}</code>
        </div>
    ` : '';

    contentEl.innerHTML = `
        <p class="font-semibold text-gray-700">Observaciones:</p>
        <div class="text-gray-800 bg-gray-50 p-3 rounded-md border">${note.content.replace(/\n/g, '<br>')}</div>
        ${arnHtml}
        <p class="text-xs text-gray-400 mt-4">Creada: ${new Date(note.timestamp).toLocaleString()}</p>
    `;

    const newEditBtn = editBtn.cloneNode(true);
    editBtn.parentNode.replaceChild(newEditBtn, editBtn);
    newEditBtn.addEventListener('click', () => { modal.classList.add('hidden'); openNotesModal(noteId); });

    const newDeleteBtn = deleteBtn.cloneNode(true);
    deleteBtn.parentNode.replaceChild(newDeleteBtn, deleteBtn);
    newDeleteBtn.addEventListener('click', () => deleteAuditorNote(noteId));

    closeBtn.onclick = () => modal.classList.add('hidden');
    modal.classList.remove('hidden');
};

const deleteAuditorNote = (noteId) => {
    const confirmation = confirm('¿Estás seguro de que quieres eliminar esta nota? Esta acción no se puede deshacer.');
    if (confirmation) {
        const noteIndex = window.auditorNotes.findIndex(note => note.id === noteId);
        if (noteIndex > -1) {
            window.auditorNotes.splice(noteIndex, 1);
            saveAuditorNotes();
            buildAuditorNotesView();
            log(`Nota con ID ${noteId} eliminada.`, 'success');
            const modal = document.getElementById('note-details-modal');
            if (modal) modal.classList.add('hidden');
        } else {
            log(`Error: No se pudo eliminar la nota con ID ${noteId}`, 'error');
        }
    }
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

    // Navegación principal
    const sidebarNav = document.getElementById('sidebar-nav');
    if (sidebarNav) sidebarNav.addEventListener('click', handleMainNavClick);

    // Menú rápido de notas
    const showNotesMenu = () => {
        const existingMenu = document.getElementById('notes-menu');
        if (existingMenu) existingMenu.remove();
        
        const menu = document.createElement('div');
        menu.id = 'notes-menu';
        menu.className = 'fixed bottom-20 right-4 bg-white border border-gray-200 rounded-lg shadow-lg z-50';
        menu.innerHTML = `
            <div class="p-2">
                <button onclick="openNotesModal()" class="w-full text-left px-3 py-2 hover:bg-gray-100 rounded flex items-center">
                    Write Note
                </button>
                <button onclick="activateElementSelector()" class="w-full text-left px-3 py-2 hover:bg-gray-100 rounded flex items-center">
                    Capture Evidence
                </button>
            </div>
        `;
        
        document.body.appendChild(menu);
        setTimeout(() => { document.addEventListener('click', closeMenu, true); }, 100);
        function closeMenu() { menu.remove(); document.removeEventListener('click', closeMenu, true); }
    };

    const openNotesButton = document.getElementById('open-notes-btn');
    if (openNotesButton) openNotesButton.addEventListener('click', () => { showNotesMenu(); });

    // Botón de análisis
    if (runAnalysisBtn) runAnalysisBtn.addEventListener('click', runAnalysisFromInputs);

    // Import/Export
    const exportBtn = document.getElementById('export-results-button');
    const importBtn = document.getElementById('import-results-button');
    const fileInput = document.getElementById('json-file-input');
    if (exportBtn) exportBtn.addEventListener('click', exportResultsToJson);
    if (importBtn && fileInput) {
        importBtn.addEventListener('click', () => fileInput.click());
        fileInput.addEventListener('change', handleJsonImport);
    }

    // Controles del log
    if (clearLogBtn) clearLogBtn.addEventListener('click', () => {
        if (logContainer) {
            logContainer.innerHTML = '';
            if (logPanel) logPanel.classList.remove('new-log');
        }
    });

    if (toggleLogBtn && logPanel) {
        toggleLogBtn.addEventListener('click', (e) => { e.stopPropagation(); minimizeLogPanel(); });
        logPanel.addEventListener('click', (e) => {
            if (logPanel.classList.contains('floating')) { e.stopPropagation(); maximizeLogPanel(); }
        });
    }

    function minimizeLogPanel() {
        if (logPanel) {
            logPanel.classList.remove('minimized');
            logPanel.classList.add('floating');
            if (toggleLogBtn) toggleLogBtn.textContent = 'Show Log';
            log('Event Log minimized to floating button', 'info');
        }
    }
    function maximizeLogPanel() {
        if (logPanel) {
            logPanel.classList.remove('floating', 'new-log');
            if (toggleLogBtn) toggleLogBtn.textContent = 'Minimize';
            log('Event Log expanded', 'info');
        }
    }

    // Modal global
    setupModalControls();

    // Vistas vacías
    views.forEach(view => { if (view.id !== 'iam-view') view.innerHTML = createInitialEmptyState(); });

    // Vista inicial
    const initialView = document.getElementById('iam-view');
    if (initialView) { initialView.classList.remove('hidden'); buildIamView(); }
    minimizeLogPanel();

    // === Auth UI wiring ===
    const $loginBtn  = document.getElementById('login-btn');
    const $logoutBtn = document.getElementById('logout-btn');
    
    if ($loginBtn)  $loginBtn.addEventListener('click', () => login());
    if ($logoutBtn) $logoutBtn.addEventListener('click', () => logout());
    
    // Pinta estado actual y vuelve a pintar cuando cambie (login/logout/expiración)
    renderAuthUI();
    onAuthChange(renderAuthUI);
    
    // (Opcional) expón por consola
    window._auth = { login, logout, renderAuthUI };
    
    log('Application initialized successfully.', 'success');

    // Exponer showNotesMenu (definido dentro)
    window.showNotesMenu = showNotesMenu;
});

// --- SELECTOR VISUAL GLOBAL ---
let selectorMode = false;
let originalStyles = new Map();

window.activateElementSelector = () => {
    if (selectorMode) return;
    selectorMode = true;
    document.body.style.cursor = 'crosshair';
    document.body.classList.add('element-selector-mode');
    
    const overlay = document.createElement('div');
    overlay.id = 'selector-overlay';
    overlay.innerHTML = `
        <div class="fixed top-4 left-1/2 transform -translate-x-1/2 bg-[#eb3496] text-white px-4 py-2 rounded-lg shadow-lg z-50">
            Click on any element to capture evidence | Press ESC to cancel
        </div>`;
    document.body.appendChild(overlay);
    
    document.addEventListener('mouseover', highlightElement, true);
    document.addEventListener('mouseout', removeHighlight, true);
    document.addEventListener('click', captureElementOnClick, true);
    document.addEventListener('keydown', handleSelectorKeydown);
};

const highlightElement = (e) => {
    if (!selectorMode) return;
    originalStyles.set(e.target, {
        outline: e.target.style.outline,
        backgroundColor: e.target.style.backgroundColor
    });
    e.target.style.outline = '2px solid #eb3496';
    e.target.style.backgroundColor = 'rgba(235, 52, 150, 0.1)';
};

const removeHighlight = (e) => {
    if (!selectorMode) return;
    const original = originalStyles.get(e.target);
    if (original) {
        e.target.style.outline = original.outline;
        e.target.style.backgroundColor = original.backgroundColor;
        originalStyles.delete(e.target);
    }
};

const captureElementOnClick = (e) => {
    if (!selectorMode) return;
    e.preventDefault();
    e.stopPropagation();
    const evidence = extractElementEvidence(e.target);
    deactivateElementSelector();
    openNotesModalWithEvidence(evidence);
};

const deactivateElementSelector = () => {
    selectorMode = false;
    document.body.style.cursor = '';
    document.body.classList.remove('element-selector-mode');
    const overlay = document.getElementById('selector-overlay');
    if (overlay) overlay.remove();
    originalStyles.forEach((originalStyle, element) => {
        element.style.outline = originalStyle.outline;
        element.style.backgroundColor = originalStyle.backgroundColor;
    });
    originalStyles.clear();
    document.removeEventListener('mouseover', highlightElement, true);
    document.removeEventListener('mouseout', removeHighlight, true);
    document.removeEventListener('click', captureElementOnClick, true);
    document.removeEventListener('keydown', handleSelectorKeydown);
};

const handleSelectorKeydown = (e) => { if (e.key === 'Escape') deactivateElementSelector(); };

const extractElementEvidence = (element) => {
    const currentView = document.querySelector('#sidebar-nav a.bg-\\[\\#eb3496\\]')?.dataset.view;
    const activeTab = document.querySelector('.tab-link.border-\\[\\#eb3496\\]')?.textContent?.trim();
    
    let evidence = {
        timestamp: new Date().toISOString(),
        section: getCurrentSectionName(),
        subSection: activeTab,
        elementType: 'Unknown Element',
        data: {},
        rawHTML: element.outerHTML.substring(0, 500)
    };
    
    const row = element.closest('tr');
    const card = element.closest('.bg-white');
    
    if (row && row.closest('tbody')) {
        evidence = { ...evidence, ...extractTableRowData(row, currentView) };
    } else if (element.closest('.bg-yellow-200') || element.textContent.includes('VIP')) {
        evidence = { ...evidence, elementType: 'Privileged User Badge', data: { issue: 'Privileged user detected', element: element.textContent.trim() } };
    } else if (element.closest('.bg-red-100') || element.textContent.includes('NO')) {
        evidence = { ...evidence, elementType: 'Security Issue Badge', data: { issue: 'Negative security indicator', status: element.textContent.trim() } };
    }
    return evidence;
};

const extractTableRowData = (row, currentView) => {
    const cells = Array.from(row.querySelectorAll('td')).map(td => td.textContent.trim());
    const extractors = {
        'iam': extractIamUserRow,
        'acm': extractAcmCertRow,
        'compute': extractComputeRow,
        'databases': extractDatabaseRow
    };
    const extractor = extractors[currentView] || extractGenericRow;
    return extractor(cells, row);
};

const extractComputeRow = (cells, row) => ({
    elementType: 'Compute Resource',
    data: {
        identifier: cells[1],
        region: cells[0],
        status: cells[4] || 'Unknown',
        issue: cells[4]?.includes('stopped') ? 'Instance stopped' : null
    }
});

const extractDatabaseRow = (cells, row) => ({
    elementType: 'Database Resource',
    data: {
        identifier: cells[1],
        region: cells[0],
        status: cells[2],
        issue: cells[3]?.includes('YES') ? 'Publicly accessible' : null
    }
});

const extractGenericRow = (cells, row) => ({ elementType: 'Table Row', data: { values: cells, cellCount: cells.length } });

const getCurrentSectionName = () => {
    const activeView = document.querySelector('#sidebar-nav a.bg-\\[\\#eb3496\\]');
    return activeView?.querySelector('div:last-child')?.textContent || 'Unknown Section';
};

const openNotesModalWithEvidence = (evidence) => {
    openNotesModal();
    setTimeout(() => {
        const titleInput = document.getElementById('notes-modal-title-input');
        const arnInput = document.getElementById('notes-modal-arn-input');
        const textarea = document.getElementById('notes-modal-textarea');
        titleInput.value = `Issue found: ${evidence.data.issue || evidence.elementType}`;
        arnInput.value = evidence.data.arn || '';
        const evidenceText = `EVIDENCE CAPTURED:\nTimestamp: ${evidence.timestamp}\nSection: ${evidence.section}\nSub-section: ${evidence.subSection || 'Main view'}\nElement Type: ${evidence.elementType}\n\nDetails:\n${JSON.stringify(evidence.data, null, 2)}\n\nAdditional Notes:\n`;
        textarea.value = evidenceText;
        textarea.focus();
        textarea.setSelectionRange(textarea.value.length, textarea.value.length);
    }, 100);
};

const extractIamUserRow = (cells, row) => ({
    elementType: 'IAM User',
    data: {
        username: cells[0]?.replace('VIP', '').trim(),
        passwordEnabled: cells[1],
        mfaEnabled: cells[3]?.includes('NO') ? 'NO MFA' : 'MFA Enabled',
        isPrivileged: row.querySelector('.bg-yellow-200') ? true : false,
        issue: cells[3]?.includes('NO') ? 'MFA not enabled' : null
    }
});

const extractAcmCertRow = (cells, row) => ({
    elementType: 'ACM Certificate',
    data: {
        domain: cells[1],
        region: cells[2],
        status: cells[3],
        expirationDate: cells[6],
        issue: cells[3]?.includes('EXPIRED') ? 'Certificate expired' : null
    }
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
window.removeResourceScope = removeResourceScope;
window.openNotesModal = openNotesModal;
window.showNoteDetails = showNoteDetails;
window.deleteAuditorNote = deleteAuditorNote;
window.activateElementSelector = activateElementSelector;
window.openModalWithVpcTags = openModalWithVpcTags;
window.setResourceScope = setResourceScope;

// === Delegación global para botones de Scope ===
document.addEventListener('click', (e) => {
  // Toggle scope inline
  const toggleBtn = e.target.closest('[data-action="toggle-scope"]');
  if (toggleBtn) {
    const arn = toggleBtn.dataset.arn;
    if (!arn) return;
    if (window.scopedResources[arn]) {
      removeResourceScope(arn);
    } else {
      setResourceScope(arn, ''); // comentario opcional
    }
    return; // evita caer al siguiente handler en el mismo click
  }
  // Abrir modal de scope
  const openBtn = e.target.closest('[data-action="open-scope-modal"]');
  if (openBtn) {
    const arn = openBtn.dataset.arn;
    const currentComment = openBtn.dataset.comment || '';
    if (arn) openScopeModal(arn, currentComment);
  }
});
