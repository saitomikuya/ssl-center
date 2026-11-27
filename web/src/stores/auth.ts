import { reactive } from 'vue'
import type { AuthMeResponse } from '@/types/api'

export const authState = reactive<{
  checked: boolean
  authenticated: boolean
  mustChangePassword: boolean
  csrfToken: string
  ip: string
}>({
  checked: false,
  authenticated: false,
  mustChangePassword: false,
  csrfToken: '',
  ip: '',
})

export function applyAuthMe(data: AuthMeResponse) {
  authState.checked = true
  authState.authenticated = data.authenticated
  authState.mustChangePassword = data.must_change_password
  authState.csrfToken = data.csrf_token || ''
  authState.ip = data.ip || ''
}

export function clearAuthState() {
  authState.checked = true
  authState.authenticated = false
  authState.mustChangePassword = false
  authState.csrfToken = ''
  authState.ip = ''
}
