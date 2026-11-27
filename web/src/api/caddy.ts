import { apiRequest } from './client'
import type {
  CaddyConflictDetails,
  CaddyContainerInfo,
  CaddyDiffResponse,
  CaddyfileResponse,
  CaddySaveResponse,
  CaddySnapshotDTO,
  CaddyValidateErrorDetails,
  CaddyValidateResponse,
  SaveCaddyfileRequest,
} from '@/types/api'

export function getCaddyfile(hostId: number) {
  return apiRequest<CaddyfileResponse>(`/hosts/${hostId}/caddy/caddyfile`)
}

export function saveCaddyfile(hostId: number, req: SaveCaddyfileRequest) {
  return apiRequest<CaddySaveResponse, CaddyConflictDetails | CaddyValidateErrorDetails>(
    `/hosts/${hostId}/caddy/caddyfile`,
    {
      method: 'PUT',
      body: req,
    },
  )
}

export function formatCaddyfile(hostId: number, content: string) {
  return apiRequest<{ content: string }>(`/hosts/${hostId}/caddy/format`, {
    method: 'POST',
    body: { content },
  })
}

export function validateCaddyfile(hostId: number, content: string) {
  return apiRequest<CaddyValidateResponse>(`/hosts/${hostId}/caddy/validate`, {
    method: 'POST',
    body: { content },
  })
}

export function reloadCaddy(hostId: number) {
  return apiRequest<CaddySaveResponse>(`/hosts/${hostId}/caddy/reload`, {
    method: 'POST',
  })
}

export function listCaddySnapshots(hostId: number) {
  return apiRequest<CaddySnapshotDTO[]>(`/hosts/${hostId}/caddy/snapshots`)
}

export function getCaddySnapshotDiff(hostId: number, snapId: number) {
  return apiRequest<CaddyDiffResponse>(`/hosts/${hostId}/caddy/snapshots/${snapId}/diff`)
}

export function rollbackCaddySnapshot(hostId: number, snapId: number) {
  return apiRequest<CaddySaveResponse>(`/hosts/${hostId}/caddy/snapshots/${snapId}/rollback`, {
    method: 'POST',
  })
}

export function getCaddyContainerInfo(hostId: number) {
  return apiRequest<CaddyContainerInfo>(`/hosts/${hostId}/caddy/container`)
}
