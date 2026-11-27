import { apiRequest } from './client'
import type { PruneResult, SettingsDTO, UpdateSettingsRequest } from '@/types/api'

export function getSettings() {
  return apiRequest<SettingsDTO>('/settings')
}

export function updateSettings(req: UpdateSettingsRequest) {
  return apiRequest<SettingsDTO>('/settings', {
    method: 'PUT',
    body: req,
  })
}

export function pruneLogs() {
  return apiRequest<PruneResult>('/settings/prune-logs', {
    method: 'POST',
  })
}
