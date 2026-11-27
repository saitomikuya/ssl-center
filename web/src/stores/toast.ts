import { reactive } from 'vue'

export type ToastType = 'success' | 'error' | 'warning' | 'info'

export interface ToastItem {
  id: number
  type: ToastType
  title?: string
  message: string
}

let nextId = 1

export const toastState = reactive<{
  items: ToastItem[]
  maintenanceActive: boolean
  maintenanceMessage: string
}>({
  items: [],
  maintenanceActive: false,
  maintenanceMessage: '',
})

export function showToast(type: ToastType, message: string, title?: string, durationMs = 4500) {
  const id = nextId++
  toastState.items.push({ id, type, title, message })
  if (durationMs > 0) {
    window.setTimeout(() => {
      dismissToast(id)
    }, durationMs)
  }
}

export function dismissToast(id: number) {
  const idx = toastState.items.findIndex((t) => t.id === id)
  if (idx !== -1) {
    toastState.items.splice(idx, 1)
  }
}

export function setMaintenanceNotice(active: boolean, message = '系统正在执行备份恢复维护中，请稍后再试。') {
  toastState.maintenanceActive = active
  toastState.maintenanceMessage = message
}
