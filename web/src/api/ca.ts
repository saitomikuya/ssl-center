import { apiRequest } from './client'
import type {
  CAAccountDTO,
  CreateCARequest,
  ExportCAKeyResponse,
  UpdateCARequest,
} from '@/types/api'

export function listCAAccounts() {
  return apiRequest<CAAccountDTO[]>('/ca-accounts')
}

export function createCAAccount(req: CreateCARequest) {
  return apiRequest<CAAccountDTO>('/ca-accounts', {
    method: 'POST',
    body: req,
  })
}

export function updateCAAccount(id: number, req: UpdateCARequest) {
  return apiRequest<CAAccountDTO>(`/ca-accounts/${id}`, {
    method: 'PUT',
    body: req,
  })
}

export function deleteCAAccount(id: number) {
  return apiRequest<{ deleted: boolean }>(`/ca-accounts/${id}`, {
    method: 'DELETE',
  })
}

export function setDefaultCAAccount(id: number) {
  return apiRequest<CAAccountDTO>(`/ca-accounts/${id}/default`, {
    method: 'POST',
  })
}

export function exportCAKey(id: number) {
  return apiRequest<ExportCAKeyResponse>(`/ca-accounts/${id}/export-key`, {
    method: 'POST',
  })
}
