/**
 * 19_reporting.js
 * Contains all logic for building and rendering the Reporting view.
 */

// --- IMPORTS ---
import { handleTabClick, log } from '../utils.js';

// --- MAIN VIEW FUNCTION (EXPORTED) ---
export const buildReportingView = () => {
    const container = document.getElementById('reporting-view');
    if (!container) return;

    container.innerHTML = `
        <header class="flex justify-between items-center mb-6">
            <div>
                <h2 class="text-2xl font-bold text-[#204071]">Reporting</h2>
                <p class="text-sm text-gray-500">Scoped inventory and audit documentation.</p>
            </div>
        </header>
        
        <div id="reporting-content">
            <!-- El contenido del inventory se cargará directamente aquí -->
        </div>
    `;
    
    buildScopedInventoryView();
};

// --- SCOPED INVENTORY FUNCTIONS ---
export const buildScopedInventoryView = () => {
    const container = document.getElementById('reporting-content');
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
                if (arn.includes(':vpc/')) {
                    const vpc = window.networkPoliciesApiData?.results?.vpcs.find(v => {
                        const vpcArn = `arn:aws:ec2:${v.Region}:${window.iamApiData?.metadata?.accountId || 'unknown'}:vpc/${v.VpcId}`;
                        return vpcArn === arn;
                    });
                    if (vpc) {
                        unifiedScopedItems.push({
                            type: 'VPC',
                            region: vpc.Region,
                            identifier: vpc.VpcId,
                            details: `CIDR: ${vpc.CidrBlock}, Default: ${vpc.IsDefault ? 'YES' : 'NO'}`,
                            comment: comment,
                            arn: arn
                        });
                    }
                } else if (arn.includes(':instance/')) {
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
                
            default:
                unifiedScopedItems.push({
                    type: service.toUpperCase(),
                    region: 'Multiple',
                    identifier: arn.split('/').pop() || arn.split(':').pop(),
                    details: 'See ARN for full details',
                    comment: comment,
                    arn: arn
                });
                break;
        }
    });

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
                        <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" fill="currentColor" viewBox="0 0 16 16">
                            <path d="M12.146.146a.5.5 0 0 1 .708 0l3 3a.5.5 0 0 1 0 .708l-10 10a.5.5 0 0 1-.168.11l-5 2a.5.5 0 0 1-.65-.65l2-5a.5.5 0 0 1 .11-.168zM11.207 2.5 13.5 4.793 14.793 3.5 12.5 1.207zm1.586 3L10.5 3.207 4 9.707V10h.5a.5.5 0 0 1 .5.5v.5h.5a.5.5 0 0 1 .5.5v.5h.293zm-9.761 5.175-.106.106-1.528 3.821 3.821-1.528.106-.106A.5.5 0 0 1 5 12.5V12h-.5a.5.5 0 0 1-.5-.5V11h-.5a.5.5 0 0 1-.468-.325"/>
                        </svg>
                    </button>
                    <button class="save-btn hidden text-green-600" data-index="${index}" title="Save">
                        <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" fill="currentColor" viewBox="0 0 16 16">
                            <path d="M12.736 3.97a.733.733 0 0 1 1.047 0c.286.289.29.756.01 1.05L7.88 12.01a.733.733 0 0 1-1.065.02L3.217 8.384a.757.757 0 0 1 0-1.06.733.733 0 0 1 1.047 0l3.052 3.093 5.4-6.425z"/>
                        </svg>
                    </button>
                    <button class="cancel-btn hidden text-gray-600" data-index="${index}" title="Cancel">
                        <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" fill="currentColor" viewBox="0 0 16 16">
                            <path d="M2.146 2.854a.5.5 0 1 1 .708-.708L8 7.293l5.146-5.147a.5.5 0 0 1 .708.708L8.707 8l5.147 5.146a.5.5 0 0 1-.708.708L8 8.707l-5.146 5.147a.5.5 0 0 1-.708-.708L7.293 8z"/>
                        </svg>
                    </button>
                    <button class="delete-btn text-red-600 hover:text-red-800" data-index="${index}" title="Delete">
                        <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" fill="currentColor" viewBox="0 0 16 16">
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

// Funciones auxiliares (enterEditMode, saveComment, etc.)
const setupScopedInventoryEvents = (items) => {
    const container = document.getElementById('reporting-content');
    if (!container) return;

    container.querySelectorAll('.edit-btn').forEach(btn => {
        btn.addEventListener('click', (e) => {
            const index = e.currentTarget.getAttribute('data-index');
            enterEditMode(index);
        });
    });

    container.querySelectorAll('.save-btn').forEach(btn => {
        btn.addEventListener('click', (e) => {
            const index = e.currentTarget.getAttribute('data-index');
            saveComment(index, items);
        });
    });

    container.querySelectorAll('.cancel-btn').forEach(btn => {
        btn.addEventListener('click', (e) => {
            const index = e.currentTarget.getAttribute('data-index');
            cancelEdit(index, items);
        });
    });

    container.querySelectorAll('.delete-btn').forEach(btn => {
        btn.addEventListener('click', (e) => {
            const index = e.currentTarget.getAttribute('data-index');
            deleteResource(index, items);
        });
    });
};

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

const saveComment = (index, items) => {
    const commentInput = document.querySelector(`[data-index="${index}"].comment-input`);
    const newComment = commentInput.value.trim();
    const arn = items[index].arn;
    
    if (window.scopedResources[arn]) {
        window.scopedResources[arn].comment = newComment;
        // Guardar en localStorage
        localStorage.setItem('audiThorScopedResources', JSON.stringify(window.scopedResources));
    }
    buildScopedInventoryView(); // Refrescar vista
};

const cancelEdit = (index, items) => {
    const originalComment = items[index].comment;
    const commentInput = document.querySelector(`[data-index="${index}"].comment-input`);
    commentInput.value = originalComment;
    exitEditMode(index);
};

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

const deleteResource = (index, items) => {
    const arn = items[index].arn;
    const resourceName = items[index].identifier;
    
    if (confirm(`¿Seguro que quieres quitar "${resourceName}" del scope?`)) {
        delete window.scopedResources[arn];
        localStorage.setItem('audiThorScopedResources', JSON.stringify(window.scopedResources));
        buildScopedInventoryView(); // Refrescar vista
    }
};