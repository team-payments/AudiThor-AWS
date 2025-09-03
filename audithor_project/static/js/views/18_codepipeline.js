/**
 * 18_codepipeline.js
 * Contains all logic for building and rendering the CodePipeline view.
 */

// --- IMPORTS ---
import { handleTabClick, createStatusBadge } from '../utils.js';

// --- SERVICE DESCRIPTIONS ---
const serviceDescriptions = {
    overview: {
        title: "AWS CodePipeline - CI/CD Security Overview",
        description: "CodePipeline is a fully managed continuous integration and continuous delivery (CI/CD) service that automates software release pipelines. It orchestrates build, test, and deployment phases with integrated security controls including artifact encryption, manual approvals, IAM-based access control, and integration with security scanning tools.",
        useCases: "Automated software delivery pipelines, multi-stage deployments (dev/staging/production), infrastructure as code (IaC) deployment automation, microservices CI/CD orchestration, compliance-driven release processes with mandatory approvals, integration with security tools for vulnerability scanning and code quality gates.",
        auditConsiderations: "Verify production pipelines have manual approval gates to prevent unauthorized deployments. Ensure artifact stores use encryption at rest and in transit. Validate pipeline IAM roles follow least privilege principles. Check integration with security tools (CodeBuild security scans, third-party vulnerability scanners). Review source code access controls and webhook security for repository integrations."
    },
    pipelines: {
        title: "Pipeline Configuration & Security Controls",
        description: "Pipeline configuration encompasses security controls across all stages of the software delivery process. Proper configuration includes encrypted artifact storage, manual approval steps for production deployments, least-privilege IAM roles, and integration with security scanning tools to maintain code quality and security posture.",
        useCases: "Production deployment controls with human oversight, automated security scanning integration, encrypted artifact management, cross-account deployment strategies, compliance-ready release processes with audit trails, integration with container security scanning and infrastructure validation.",
        auditConsiderations: "Ensure production pipelines require manual approval before deployment stages. Verify artifact stores are encrypted with appropriate KMS keys. Check pipeline service roles have minimal required permissions. Validate integration with security tools like CodeBuild for SAST/DAST scanning, or third-party security tools. Review source provider configurations for secure webhook handling and access token management."
    },
    security: {
        title: "Security Analysis & Risk Assessment",
        description: "Security analysis focuses on identifying pipelines with insufficient security controls that could lead to unauthorized deployments, data exposure, or compliance violations. Key areas include missing manual approvals, unencrypted artifacts, overly permissive IAM roles, and lack of security scanning integration.",
        useCases: "Risk assessment for production pipelines, compliance validation for regulated environments, security gap identification in CI/CD processes, audit preparation for pipeline security controls, remediation planning for security deficiencies.",
        auditConsiderations: "Prioritize pipelines that deploy to production environments without manual approval steps. Focus on pipelines with unencrypted artifact stores that may expose sensitive code or configuration data. Review pipelines lacking integration with security scanning tools that could deploy vulnerable code. Assess pipeline IAM roles for excessive permissions that could enable privilege escalation."
    }
};

// --- RENDERIZADO DE ESTADO VACÍO ---
const renderEmptyState = (message) => {
    return `
        <div class="bg-white p-6 rounded-xl border border-gray-100">
            <div class="text-center">
                <svg class="mx-auto h-12 w-12 text-gray-400" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" />
                </svg>
                <h3 class="mt-2 text-sm font-medium text-gray-900">No CodePipeline pipelines found</h3>
                <p class="mt-1 text-sm text-gray-500">${message}</p>
            </div>
        </div>
    `;
};

// --- RENDERIZADOR DE DESCRIPCIÓN DE SERVICIOS (ACTUALIZADO AL ESTILO ECR) ---
const renderServiceDescription = (serviceInfo) => {
    return `
        <div class="bg-white border border-gray-200 rounded-lg p-6 mb-6">
            <h3 class="text-lg font-semibold text-gray-800 mb-3">${serviceInfo.title}</h3>
            <div class="space-y-3">
                <div>
                    <h4 class="text-sm font-medium text-gray-700 mb-1">Definition:</h4>
                    <p class="text-sm text-gray-600">${serviceInfo.description}</p>
                </div>
                <div>
                    <h4 class="text-sm font-medium text-gray-700 mb-1">Common Use Cases:</h4>
                    <p class="text-sm text-gray-600">${serviceInfo.useCases}</p>
                </div>
                <div class="bg-yellow-50 border border-yellow-200 rounded p-3">
                    <h4 class="text-sm font-medium text-yellow-800 mb-1">Audit Considerations:</h4>
                    <p class="text-sm text-yellow-700">${serviceInfo.auditConsiderations}</p>
                </div>
            </div>
        </div>
    `;
};

// --- FUNCIÓN PARA CREAR TARJETAS DE RESUMEN ---
const createCodePipelineSummaryCardsHtml = (pipelines) => {
    const totalPipelines = pipelines.length;
    const encryptedPipelines = pipelines.filter(p => p.IsEncrypted).length;
    const pipelinesWithApproval = pipelines.filter(p => p.HasManualApproval).length;
    const pipelinesWithSecurity = pipelines.filter(p => p.HasSecurityScan).length;
    
    // Agrupar por región
    const regionCounts = {};
    pipelines.forEach(p => {
        regionCounts[p.Region] = (regionCounts[p.Region] || 0) + 1;
    });
    
    const topRegions = Object.entries(regionCounts)
        .sort(([,a], [,b]) => b - a)
        .slice(0, 5)
        .map(([region, count]) => `<span class="inline-block bg-gray-100 text-gray-800 text-xs px-2 py-1 rounded-full mr-2 mb-1">${region}: ${count}</span>`)
        .join('');

    return `
        <div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6 mb-6">
            <div class="bg-white p-6 rounded-xl border border-gray-100">
                <div class="flex items-center">
                    <div class="flex-1">
                        <p class="text-sm font-medium text-gray-600">Total Pipelines</p>
                        <p class="text-2xl font-bold text-[#204071]">${totalPipelines}</p>
                    </div>
                    <div class="flex-shrink-0">
                        <svg class="h-8 w-8 text-blue-500" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" />
                        </svg>
                    </div>
                </div>
            </div>

            <div class="bg-white p-6 rounded-xl border border-gray-100">
                <div class="flex items-center">
                    <div class="flex-1">
                        <p class="text-sm font-medium text-gray-600">Security Issues</p>
                        <p class="text-2xl font-bold text-red-600">${pipelines.filter(p => !p.IsEncrypted || !p.HasManualApproval || !p.HasSecurityScan).length}</p>
                        <p class="text-xs text-gray-500">Pipelines with risks</p>
                    </div>
                    <div class="flex-shrink-0">
                        <svg class="h-8 w-8 text-red-500" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
                        </svg>
                    </div>
                </div>
            </div>

            <div class="bg-white p-6 rounded-xl border border-gray-100">
                <div class="flex items-center">
                    <div class="flex-1">
                        <p class="text-sm font-medium text-gray-600">Manual Approval</p>
                        <p class="text-2xl font-bold text-green-600">${pipelinesWithApproval}</p>
                        <p class="text-xs text-gray-500">${totalPipelines > 0 ? Math.round((pipelinesWithApproval/totalPipelines)*100) : 0}% with approval</p>
                    </div>
                    <div class="flex-shrink-0">
                        <svg class="h-8 w-8 text-green-500" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" />
                        </svg>
                    </div>
                </div>
            </div>

            <div class="bg-white p-6 rounded-xl border border-gray-100">
                <div class="flex items-center">
                    <div class="flex-1">
                        <p class="text-sm font-medium text-gray-600">Encrypted Artifacts</p>
                        <p class="text-2xl font-bold text-blue-600">${encryptedPipelines}</p>
                        <p class="text-xs text-gray-500">${totalPipelines > 0 ? Math.round((encryptedPipelines/totalPipelines)*100) : 0}% encrypted</p>
                    </div>
                    <div class="flex-shrink-0">
                        <svg class="h-8 w-8 text-blue-500" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z" />
                        </svg>
                    </div>
                </div>
            </div>
        </div>

        <div class="bg-white p-6 rounded-xl border border-gray-100 mb-6">
            <h3 class="text-lg font-semibold text-[#204071] mb-4">Pipelines by Region</h3>
            <div class="flex flex-wrap">
                ${topRegions}
            </div>
        </div>
    `;
};

// --- FUNCIÓN PARA RENDERIZAR ANÁLISIS DE SEGURIDAD ---
const renderSecurityAnalysisTable = (pipelines) => {
    const securityIssues = pipelines.filter(p => !p.IsEncrypted || !p.HasManualApproval || !p.HasSecurityScan);
    
    if (securityIssues.length === 0) {
        return `
            <div class="bg-green-50 border border-green-200 rounded-lg p-4">
                <div class="flex">
                    <svg class="h-5 w-5 text-green-400" viewBox="0 0 20 20" fill="currentColor">
                        <path fill-rule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zm3.707-9.293a1 1 0 00-1.414-1.414L9 10.586 7.707 9.293a1 1 0 00-1.414 1.414l2 2a1 1 0 001.414 0l4-4z" clip-rule="evenodd" />
                    </svg>
                    <div class="ml-3">
                        <h3 class="text-sm font-medium text-green-800">All pipelines follow security best practices</h3>
                        <p class="mt-1 text-sm text-green-700">No security issues detected in your CodePipeline configurations.</p>
                    </div>
                </div>
            </div>
        `;
    }

    return `
        <div class="bg-white rounded-xl border border-gray-100 overflow-hidden">
            <div class="px-6 py-4 border-b border-gray-100">
                <h3 class="text-lg font-semibold text-[#204071]">Security Issues Found (${securityIssues.length})</h3>
                <p class="text-sm text-gray-600 mt-1">Pipelines that may need attention for security compliance</p>
            </div>
            <div class="overflow-x-auto">
                <table class="min-w-full divide-y divide-gray-200">
                    <thead class="bg-gray-50">
                        <tr>
                            <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Pipeline</th>
                            <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Region</th>
                            <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Encrypted</th>
                            <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Manual Approval</th>
                            <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Security Scan</th>
                            <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Risk Level</th>
                            <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Recommendations</th>
                        </tr>
                    </thead>
                    <tbody class="bg-white divide-y divide-gray-200">
                        ${securityIssues.map(pipeline => {
                            const issues = [];
                            if (!pipeline.IsEncrypted) issues.push('Unencrypted artifacts');
                            if (!pipeline.HasManualApproval) issues.push('No manual approval');
                            if (!pipeline.HasSecurityScan) issues.push('No security scanning');
                            
                            // Calculate risk level
                            let riskLevel = 'Medium Risk';
                            let riskColor = 'yellow';
                            if (issues.length >= 2) {
                                riskLevel = 'High Risk';
                                riskColor = 'red';
                            } else if (issues.length === 1 && pipeline.HasManualApproval) {
                                riskLevel = 'Low Risk';
                                riskColor = 'green';
                            }
                            
                            const recommendations = [];
                            if (!pipeline.IsEncrypted) recommendations.push('Enable encryption');
                            if (!pipeline.HasManualApproval) recommendations.push('Add manual approval');
                            if (!pipeline.HasSecurityScan) recommendations.push('Integrate security scanning');
                            
                            return `
                                <tr class="hover:bg-gray-50">
                                    <td class="px-6 py-4 whitespace-nowrap">
                                        <div class="text-sm font-medium text-gray-900">${pipeline.Name}</div>
                                        <div class="text-sm text-gray-500">${pipeline.SourceProvider}</div>
                                    </td>
                                    <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-500">${pipeline.Region}</td>
                                    <td class="px-6 py-4 whitespace-nowrap">
                                        ${createStatusBadge(pipeline.IsEncrypted ? 'Yes' : 'No', pipeline.IsEncrypted ? 'success' : 'error')}
                                    </td>
                                    <td class="px-6 py-4 whitespace-nowrap">
                                        ${createStatusBadge(pipeline.HasManualApproval ? 'Yes' : 'No', pipeline.HasManualApproval ? 'success' : 'warning')}
                                    </td>
                                    <td class="px-6 py-4 whitespace-nowrap">
                                        ${createStatusBadge(pipeline.HasSecurityScan ? 'Yes' : 'No', pipeline.HasSecurityScan ? 'success' : 'warning')}
                                    </td>
                                    <td class="px-6 py-4 whitespace-nowrap">
                                        <span class="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium bg-${riskColor}-100 text-${riskColor}-800">${riskLevel}</span>
                                    </td>
                                    <td class="px-6 py-4 text-sm text-gray-600">${recommendations.join(', ')}</td>
                                </tr>
                            `;
                        }).join('')}
                    </tbody>
                </table>
            </div>
        </div>
    `;
};

// --- FUNCIÓN PARA RENDERIZAR TABLA COMPLETA DE PIPELINES ---
const renderPipelinesTable = (pipelines) => {
    if (pipelines.length === 0) {
        return renderEmptyState("No CodePipeline pipelines found in any region");
    }

    return `
        <div class="bg-white rounded-xl border border-gray-100 overflow-hidden">
            <div class="px-6 py-4 border-b border-gray-100">
                <h3 class="text-lg font-semibold text-[#204071]">All CodePipeline Pipelines (${pipelines.length})</h3>
                <p class="text-sm text-gray-600 mt-1">Complete pipeline inventory with configuration details</p>
            </div>
            <div class="overflow-x-auto">
                <table class="min-w-full divide-y divide-gray-200">
                    <thead class="bg-gray-50">
                        <tr>
                            <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Name</th>
                            <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Region</th>
                            <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Source</th>
                            <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Encrypted</th>
                            <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Manual Approval</th>
                            <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Security Scan</th>
                            <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">IAM Role</th>
                            <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Last Updated</th>
                        </tr>
                    </thead>
                    <tbody class="bg-white divide-y divide-gray-200">
                        ${pipelines.map(pipeline => {
                            const updatedDate = pipeline.Updated ? new Date(pipeline.Updated).toLocaleDateString() : 'N/A';
                            const roleName = pipeline.RoleArn ? pipeline.RoleArn.split('/').pop() : 'N/A';
                            
                            return `
                                <tr class="hover:bg-gray-50">
                                    <td class="px-6 py-4 whitespace-nowrap">
                                        <div class="text-sm font-medium text-gray-900">${pipeline.Name}</div>
                                        ${pipeline.Error ? '<div class="text-xs text-red-500">Limited access</div>' : ''}
                                    </td>
                                    <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-500">${pipeline.Region}</td>
                                    <td class="px-6 py-4 whitespace-nowrap">
                                        <div class="text-sm text-gray-900">${pipeline.SourceProvider}</div>
                                        ${pipeline.SourceDetails?.Owner ? `<div class="text-xs text-gray-500">${pipeline.SourceDetails.Owner}/${pipeline.SourceDetails.Repo || 'N/A'}</div>` : ''}
                                    </td>
                                    <td class="px-6 py-4 whitespace-nowrap">
                                        ${createStatusBadge(pipeline.IsEncrypted ? 'Yes' : 'No', pipeline.IsEncrypted ? 'success' : 'error')}
                                    </td>
                                    <td class="px-6 py-4 whitespace-nowrap">
                                        ${createStatusBadge(pipeline.HasManualApproval ? 'Yes' : 'No', pipeline.HasManualApproval ? 'success' : 'warning')}
                                    </td>
                                    <td class="px-6 py-4 whitespace-nowrap">
                                        ${createStatusBadge(pipeline.HasSecurityScan ? 'Yes' : 'No', pipeline.HasSecurityScan ? 'success' : 'warning')}
                                    </td>
                                    <td class="px-6 py-4 whitespace-nowrap">
                                        <div class="text-xs text-gray-600 font-mono max-w-32 truncate" title="${pipeline.RoleArn}">${roleName}</div>
                                    </td>
                                    <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-500">${updatedDate}</td>
                                </tr>
                            `;
                        }).join('')}
                    </tbody>
                </table>
            </div>
        </div>
    `;
};

// --- MAIN VIEW FUNCTION (EXPORTED) ---
export const buildCodePipelineView = () => {
    const container = document.getElementById('codepipeline-view');
    if (!container) {
        console.error('CodePipeline container not found');
        return;
    }

    // Verificar si hay datos de la API
    if (!window.codepipelineApiData) {
        container.innerHTML = `
            <header class="flex justify-between items-center mb-6">
                <div>
                    <h2 class="text-2xl font-bold text-[#204071]">CodePipeline</h2>
                    <p class="text-sm text-gray-500">No data available</p>
                </div>
            </header>
            <div class="bg-yellow-50 border border-yellow-200 rounded-lg p-4">
                <div class="flex">
                    <svg class="h-5 w-5 text-yellow-400" viewBox="0 0 20 20" fill="currentColor">
                        <path fill-rule="evenodd" d="M8.257 3.099c.765-1.36 2.722-1.36 3.486 0l5.58 9.92c.75 1.334-.213 2.98-1.742 2.98H4.42c-1.53 0-2.493-1.646-1.743-2.98l5.58-9.92zM11 13a1 1 0 11-2 0 1 1 0 012 0zm-1-8a1 1 0 00-1 1v3a1 1 0 002 0V6a1 1 0 00-1-1z" clip-rule="evenodd" />
                    </svg>
                    <div class="ml-3">
                        <h3 class="text-sm font-medium text-yellow-800">CodePipeline data not available</h3>
                        <p class="mt-1 text-sm text-yellow-700">Run a full scan to collect CodePipeline information.</p>
                    </div>
                </div>
            </div>
        `;
        return;
    }

    const { pipelines = [] } = window.codepipelineApiData.results || {};
    const executionDate = window.codepipelineApiData.metadata?.executionDate || 'N/A';
    
    console.log('CodePipeline data:', { pipelines: pipelines.length, data: pipelines });
    
    // Si no hay pipelines, mostrar mensaje explicativo pero no detener el renderizado
    if (pipelines.length === 0) {
        container.innerHTML = `
            <header class="flex justify-between items-center mb-6">
                <div>
                    <h2 class="text-2xl font-bold text-[#204071]">CodePipeline</h2>
                    <p class="text-sm text-gray-500">${executionDate}</p>
                </div>
            </header>
            ${renderServiceDescription(serviceDescriptions.overview)}
            ${renderEmptyState("This AWS account does not have any CodePipeline pipelines configured. This could indicate that the service is not in use for automated deployments.")}
        `;
        return;
    }

    const securityIssues = pipelines.filter(p => !p.IsEncrypted || !p.HasManualApproval || !p.HasSecurityScan).length;
    
    container.innerHTML = `
        <header class="flex justify-between items-center mb-6">
            <div>
                <h2 class="text-2xl font-bold text-[#204071]">CodePipeline</h2>
                <p class="text-sm text-gray-500">${executionDate}</p>
            </div>
        </header>

        <div class="bg-blue-50 border border-blue-200 rounded-lg p-4 mb-6">
            <h3 class="text-sm font-semibold text-blue-800 mb-2">Audit Guidance</h3>
            <p class="text-sm text-blue-700">Review CodePipeline configurations for comprehensive security controls including artifact encryption, manual approval gates, IAM role permissions, and integration with security scanning tools. Focus on identifying pipelines with missing security controls and compliance gaps.</p>
        </div>

        <div class="border-b border-gray-200 mb-6">
            <nav class="-mb-px flex flex-wrap space-x-6" id="codepipeline-tabs">
                <a href="#" data-tab="cp-summary-content" class="tab-link py-3 px-1 border-b-2 border-[#eb3496] text-[#eb3496] font-semibold text-sm">Summary</a>
                <a href="#" data-tab="cp-security-content" class="tab-link py-3 px-1 border-b-2 border-transparent text-gray-500 hover:text-gray-700 font-medium text-sm">Security Analysis (${securityIssues})</a>
                <a href="#" data-tab="cp-details-content" class="tab-link py-3 px-1 border-b-2 border-transparent text-gray-500 hover:text-gray-700 font-medium text-sm">Pipeline Details (${pipelines.length})</a>
            </nav>
        </div>

        <div id="codepipeline-tab-content-container">
            <div id="cp-summary-content" class="codepipeline-tab-content">${createCodePipelineSummaryCardsHtml(pipelines)}</div>
            <div id="cp-security-content" class="codepipeline-tab-content hidden">
                ${renderServiceDescription(serviceDescriptions.security)}
                ${renderSecurityAnalysisTable(pipelines)}
            </div>
            <div id="cp-details-content" class="codepipeline-tab-content hidden">
                ${renderServiceDescription(serviceDescriptions.pipelines)}
                ${renderPipelinesTable(pipelines)}
            </div>
        </div>
    `;

    const tabsNav = container.querySelector('#codepipeline-tabs');
    if (tabsNav) tabsNav.addEventListener('click', handleTabClick(tabsNav, '.codepipeline-tab-content'));
};