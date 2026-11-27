import { apiRequest } from './client'
import type { AuthMeResponse, ChangePasswordRequest, LoginRequest } from '@/types/api'

export function getHealth() {
  return apiRequest<{ status: string }>('/health', { skipAuthRedirect: true })
}

export function login(req: LoginRequest) {
  return apiRequest<AuthMeResponse>('/auth/login', {
    method: 'POST',
    body: req,
    skipAuthRedirect: true,
  })
}

export function logout() {
  return apiRequest<{ logged_out: boolean }>('/auth/logout', {
    method: 'POST',
    skipAuthRedirect: true,
  })
}

export function getMe() {
  return apiRequest<AuthMeResponse>('/auth/me', {
    skipAuthRedirect: true,
  })
}

export function changePassword(req: ChangePasswordRequest) {
  return apiRequest<{ password_changed: boolean }>('/auth/change-password', {
    method: 'POST',
    body: req,
    // Wrong current_password returns 401 UNAUTHORIZED; do not bounce to /login
    skipAuthRedirect: true,
  })
}
