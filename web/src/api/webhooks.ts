import { apiRequest } from './client'
import type {
  CreateWebhookRequest,
  UpdateWebhookRequest,
  WebhookDTO,
  WebhookTestResponse,
} from '@/types/api'

export function listWebhooks() {
  return apiRequest<WebhookDTO[]>('/webhooks')
}

export function createWebhook(req: CreateWebhookRequest) {
  return apiRequest<WebhookDTO>('/webhooks', {
    method: 'POST',
    body: req,
  })
}

export function updateWebhook(id: number, req: UpdateWebhookRequest) {
  return apiRequest<WebhookDTO>(`/webhooks/${id}`, {
    method: 'PUT',
    body: req,
  })
}

export function deleteWebhook(id: number) {
  return apiRequest<{ deleted: boolean }>(`/webhooks/${id}`, {
    method: 'DELETE',
  })
}

export function testWebhook(id: number) {
  return apiRequest<WebhookTestResponse>(`/webhooks/${id}/test`, {
    method: 'POST',
  })
}
