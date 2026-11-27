import { apiRequest } from './client'
import type {
  CreateDNSRequest,
  DNSCredentialDTO,
  DNSTestResponse,
  DNSZonesResponse,
  UpdateDNSRequest,
} from '@/types/api'

export function listDNSCredentials() {
  return apiRequest<DNSCredentialDTO[]>('/dns-credentials')
}

export function createDNSCredential(req: CreateDNSRequest) {
  return apiRequest<DNSCredentialDTO>('/dns-credentials', {
    method: 'POST',
    body: req,
  })
}

export function updateDNSCredential(id: number, req: UpdateDNSRequest) {
  return apiRequest<DNSCredentialDTO>(`/dns-credentials/${id}`, {
    method: 'PUT',
    body: req,
  })
}

export function deleteDNSCredential(id: number) {
  return apiRequest<{ deleted: boolean }>(`/dns-credentials/${id}`, {
    method: 'DELETE',
  })
}

export function testDNSCredential(id: number) {
  return apiRequest<DNSTestResponse>(`/dns-credentials/${id}/test`, {
    method: 'POST',
  })
}

export function matchDNSZones(id: number, domain: string) {
  const qs = new URLSearchParams({ domain }).toString()
  return apiRequest<DNSZonesResponse>(`/dns-credentials/${id}/zones?${qs}`)
}
