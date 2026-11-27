import { apiDownload, apiRequest } from './client'
import type {
  CertificateDTO,
  CertJobDTO,
  CertPEMRequest,
  CertPEMResponse,
  CreateCertRequest,
  IssueCertResponse,
  UpdateCertRequest,
} from '@/types/api'

export function listCertificates() {
  return apiRequest<CertificateDTO[]>('/certificates')
}

export function getCertificate(id: number) {
  return apiRequest<CertificateDTO>(`/certificates/${id}`)
}

export function createCertificate(req: CreateCertRequest) {
  return apiRequest<CertificateDTO>('/certificates', {
    method: 'POST',
    body: req,
  })
}

export function updateCertificate(id: number, req: UpdateCertRequest) {
  return apiRequest<CertificateDTO>(`/certificates/${id}`, {
    method: 'PUT',
    body: req,
  })
}

export function deleteCertificate(id: number) {
  return apiRequest<{ deleted: boolean }>(`/certificates/${id}`, {
    method: 'DELETE',
  })
}

export function issueCertificate(id: number) {
  return apiRequest<IssueCertResponse>(`/certificates/${id}/issue`, {
    method: 'POST',
  })
}

export function listCertificateJobs(id: number) {
  return apiRequest<CertJobDTO[]>(`/certificates/${id}/jobs`)
}

export function getCertJob(jobId: number) {
  return apiRequest<CertJobDTO>(`/cert-jobs/${jobId}`)
}

export function getCertJobStreamUrl(jobId: number): string {
  return `/api/v1/cert-jobs/${jobId}/stream`
}

export function exportCertificatePEM(id: number, req: CertPEMRequest) {
  return apiRequest<CertPEMResponse>(`/certificates/${id}/pem`, {
    method: 'POST',
    body: req,
  })
}

export function downloadCertificateBundle(id: number) {
  return apiDownload(`/certificates/${id}/bundle.zip`, 'GET', `cert_${id}.zip`)
}
