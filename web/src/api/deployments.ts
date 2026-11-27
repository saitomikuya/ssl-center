import { apiRequest } from './client'
import type {
  CreateDeploymentRequest,
  DeploymentDTO,
  DeployLog,
  UpdateDeploymentRequest,
} from '@/types/api'

export function listCertificateDeployments(certId: number) {
  return apiRequest<DeploymentDTO[]>(`/certificates/${certId}/deployments`)
}

export function createCertificateDeployment(certId: number, req: CreateDeploymentRequest) {
  return apiRequest<DeploymentDTO>(`/certificates/${certId}/deployments`, {
    method: 'POST',
    body: req,
  })
}

export function updateDeployment(id: number, req: UpdateDeploymentRequest) {
  return apiRequest<DeploymentDTO>(`/deployments/${id}`, {
    method: 'PUT',
    body: req,
  })
}

export function deleteDeployment(id: number) {
  return apiRequest<{ deleted: boolean }>(`/deployments/${id}`, {
    method: 'DELETE',
  })
}

export function pushDeployment(id: number) {
  return apiRequest<DeployLog>(`/deployments/${id}/push`, {
    method: 'POST',
  })
}

export function listDeploymentLogs(id: number) {
  return apiRequest<DeployLog[]>(`/deployments/${id}/logs`)
}
