import { authState, clearAuthState } from '@/stores/auth'
import { setMaintenanceNotice, showToast } from '@/stores/toast'
import type { ApiEnvelope } from '@/types/api'

export class ApiError<T = unknown> extends Error {
  status: number
  code: string
  details?: T

  constructor(status: number, code: string, message: string, details?: T) {
    super(message)
    this.name = 'ApiError'
    this.status = status
    this.code = code
    this.details = details
  }
}

const API_BASE = '/api/v1'
const MUTATING_METHODS = new Set(['POST', 'PUT', 'PATCH', 'DELETE'])

type NavigateFn = (path: string) => void
let navigatorFn: NavigateFn | null = null

export function registerApiNavigator(fn: NavigateFn) {
  navigatorFn = fn
}

function redirectTo(path: string) {
  if (navigatorFn) {
    navigatorFn(path)
  } else if (window.location.pathname !== path) {
    window.location.assign(path)
  }
}

export interface RequestOptions {
  method?: string
  body?: unknown
  skipAuthRedirect?: boolean
  suppressGlobalToast?: boolean
}

function handleGlobalError(status: number, code: string, message: string, opts: RequestOptions) {
  if (status === 401 && !opts.skipAuthRedirect) {
    clearAuthState()
    if (window.location.pathname !== '/login') {
      showToast('warning', '登录会话已失效，请重新登录')
      redirectTo('/login')
    }
    return
  }

  if (status === 403 && code === 'PASSWORD_CHANGE_REQUIRED') {
    authState.mustChangePassword = true
    if (window.location.pathname !== '/change-password') {
      showToast('warning', '检测到初始密码尚未修改，请先修改管理员密码')
      redirectTo('/change-password')
    }
    return
  }

  if (status === 503 && code === 'MAINTENANCE_IN_PROGRESS') {
    setMaintenanceNotice(true, message || '系统正在执行备份恢复维护中，请稍后再试')
    if (!opts.suppressGlobalToast) {
      showToast('warning', message || '系统正在维护中，请稍后再试', '系统维护中')
    }
  }
}

export async function apiRequest<T, E = unknown>(
  path: string,
  options: RequestOptions = {},
): Promise<T> {
  const method = (options.method || 'GET').toUpperCase()
  const headers: Record<string, string> = {
    Accept: 'application/json',
  }

  if (MUTATING_METHODS.has(method) && authState.csrfToken) {
    headers['X-CSRF-Token'] = authState.csrfToken
  }

  let body: BodyInit | undefined
  if (options.body !== undefined) {
    headers['Content-Type'] = 'application/json'
    body = JSON.stringify(options.body)
  }

  const res = await fetch(`${API_BASE}${path}`, {
    method,
    headers,
    body,
    credentials: 'include',
  })

  if (res.ok && authState.authenticated) {
    // Clear maintenance notice once a request succeeds
    setMaintenanceNotice(false)
  }

  let payload: ApiEnvelope<T, E> | null = null
  const contentType = res.headers.get('content-type') || ''
  if (contentType.includes('application/json')) {
    try {
      payload = (await res.json()) as ApiEnvelope<T, E>
    } catch {
      payload = null
    }
  }

  if (!res.ok || !payload || !payload.ok) {
    const code = payload?.error?.code || `HTTP_${res.status}`
    const message = payload?.error?.message || res.statusText || '请求失败'
    const details = payload?.error?.details
    handleGlobalError(res.status, code, message, options)
    throw new ApiError<E>(res.status, code, message, details)
  }

  return payload.data as T
}

export async function apiUpload<T>(path: string, formData: FormData): Promise<T> {
  const headers: Record<string, string> = {
    Accept: 'application/json',
  }
  if (authState.csrfToken) {
    headers['X-CSRF-Token'] = authState.csrfToken
  }

  const res = await fetch(`${API_BASE}${path}`, {
    method: 'POST',
    headers,
    body: formData,
    credentials: 'include',
  })

  let payload: ApiEnvelope<T> | null = null
  try {
    payload = (await res.json()) as ApiEnvelope<T>
  } catch {
    payload = null
  }

  if (!res.ok || !payload || !payload.ok) {
    const code = payload?.error?.code || `HTTP_${res.status}`
    const message = payload?.error?.message || res.statusText || '上传失败'
    handleGlobalError(res.status, code, message, {})
    throw new ApiError(res.status, code, message, payload?.error?.details)
  }

  return payload.data as T
}

export async function apiDownload(
  path: string,
  method: 'GET' | 'POST' = 'GET',
  defaultFilename = 'download.bin',
): Promise<void> {
  const headers: Record<string, string> = {}
  if (MUTATING_METHODS.has(method) && authState.csrfToken) {
    headers['X-CSRF-Token'] = authState.csrfToken
  }

  const res = await fetch(`${API_BASE}${path}`, {
    method,
    headers,
    credentials: 'include',
  })

  if (!res.ok) {
    let code = `HTTP_${res.status}`
    let message = res.statusText || '下载失败'
    let details: unknown
    try {
      const errJson = (await res.json()) as ApiEnvelope
      if (errJson?.error) {
        code = errJson.error.code || code
        message = errJson.error.message || message
        details = errJson.error.details
      }
    } catch {
      // ignore non-json error
    }
    handleGlobalError(res.status, code, message, {})
    throw new ApiError(res.status, code, message, details)
  }

  const disposition = res.headers.get('content-disposition') || ''
  let filename = defaultFilename
  const utf8Match = /filename\*=UTF-8''([^;]+)/i.exec(disposition)
  const plainMatch = /filename="?([^";]+)"?/i.exec(disposition)
  if (utf8Match && utf8Match[1]) {
    filename = decodeURIComponent(utf8Match[1])
  } else if (plainMatch && plainMatch[1]) {
    filename = plainMatch[1]
  }

  const blob = await res.blob()
  const url = URL.createObjectURL(blob)
  const a = document.createElement('a')
  a.href = url
  a.download = filename
  document.body.appendChild(a)
  a.click()
  document.body.removeChild(a)
  URL.revokeObjectURL(url)
}
