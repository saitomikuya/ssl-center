import { apiRequest } from './client'
import type {
  CreateHostRequest,
  DeploymentDTO,
  HostDTO,
  HostTestResult,
  UpdateHostRequest,
} from '@/types/api'

export function listHosts() {
  return apiRequest<HostDTO[]>('/hosts')
}

export function getHost(id: number) {
  return apiRequest<HostDTO>(`/hosts/${id}`)
}

export function createHost(req: CreateHostRequest) {
  return apiRequest<HostDTO>('/hosts', {
    method: 'POST',
    body: req,
  })
}

export function updateHost(id: number, req: UpdateHostRequest) {
  return apiRequest<HostDTO>(`/hosts/${id}`, {
    method: 'PUT',
    body: req,
  })
}

export function deleteHost(id: number) {
  return apiRequest<{ deleted: boolean }>(`/hosts/${id}`, {
    method: 'DELETE',
  })
}

export function testHostConnection(id: number) {
  return apiRequest<HostTestResult>(`/hosts/${id}/test`, {
    method: 'POST',
  })
}

export function resetHostKey(id: number) {
  return apiRequest<HostDTO>(`/hosts/${id}/reset-host-key`, {
    method: 'POST',
  })
}

export function listHostDeployments(id: number) {
  return apiRequest<DeploymentDTO[]>(`/hosts/${id}/deployments`)
}
