import { apiDownload, apiUpload } from './client'
import type { RestoreResult } from '@/types/api'

export function exportBackup() {
  return apiDownload('/backup/export', 'POST', 'ssl-center-backup.tar.gz')
}

export function restoreBackup(file: File) {
  const form = new FormData()
  form.append('file', file)
  return apiUpload<RestoreResult>('/backup/restore', form)
}
