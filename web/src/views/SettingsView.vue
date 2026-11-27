<script setup lang="ts">
import { onMounted, reactive, ref } from 'vue'
import { useRouter } from 'vue-router'
import {
  Bell,
  Clock,
  Download,
  Edit3,
  HardDriveDownload,
  KeyRound,
  Plus,
  Send,
  Trash2,
  Upload,
} from 'lucide-vue-next'
import { changePassword } from '@/api/auth'
import { exportBackup, restoreBackup } from '@/api/backup'
import { ApiError } from '@/api/client'
import { getSettings, pruneLogs, updateSettings } from '@/api/settings'
import {
  createWebhook,
  deleteWebhook,
  listWebhooks,
  testWebhook,
  updateWebhook,
} from '@/api/webhooks'
import ConfirmDialog from '@/components/ui/ConfirmDialog.vue'
import ModalDialog from '@/components/ui/ModalDialog.vue'
import StatusBadge from '@/components/ui/StatusBadge.vue'
import { clearAuthState } from '@/stores/auth'
import { showToast } from '@/stores/toast'
import { formatDateTime } from '@/utils/format'
import type { PruneResult, RestoreResult, WebhookDTO, WebhookEventName } from '@/types/api'

const router = useRouter()

// ============================================================================
// Scheduler & Log Retention
// ============================================================================
const settingsLoading = ref(false)
const settingsSaving = ref(false)
const pruning = ref(false)
const pruneResult = ref<PruneResult | null>(null)

const settingsForm = reactive({
  inspect_time: '03:00',
  renew_before_days: 30,
  expiring_warn_days: 7,
  log_retention_days: 30,
  log_max_rows: 5000,
})

async function loadSettings() {
  settingsLoading.value = true
  try {
    const s = await getSettings()
    Object.assign(settingsForm, s)
  } catch (err) {
    showToast('error', err instanceof Error ? err.message : '加载系统配置失败')
  } finally {
    settingsLoading.value = false
  }
}

async function saveSettings() {
  settingsSaving.value = true
  try {
    const updated = await updateSettings({
      inspect_time: settingsForm.inspect_time,
      renew_before_days: Number(settingsForm.renew_before_days),
      expiring_warn_days: Number(settingsForm.expiring_warn_days),
      log_retention_days: Number(settingsForm.log_retention_days),
      log_max_rows: Number(settingsForm.log_max_rows),
    })
    Object.assign(settingsForm, updated)
    showToast('success', '调度与日志保留策略已保存')
  } catch (err) {
    showToast('error', err instanceof Error ? err.message : '保存设置失败')
  } finally {
    settingsSaving.value = false
  }
}

async function handlePruneLogs() {
  pruning.value = true
  try {
    const res = await pruneLogs()
    pruneResult.value = res
    showToast('success', `日志清理完成，共删除 ${res.total_deleted} 条记录`)
  } catch (err) {
    showToast('error', err instanceof Error ? err.message : '日志清理失败')
  } finally {
    pruning.value = false
  }
}

// ============================================================================
// Webhooks
// ============================================================================
const ALL_WEBHOOK_EVENTS: { value: WebhookEventName; label: string; desc: string }[] = [
  { value: 'cert.issue_failed', label: 'cert.issue_failed', desc: '证书签发或续期失败' },
  { value: 'cert.expiring_soon', label: 'cert.expiring_soon', desc: '证书临近过期预警' },
  { value: 'deploy.failed', label: 'deploy.failed', desc: '部署推送或 TLS 校验失败' },
  { value: 'caddy.reload_failed', label: 'caddy.reload_failed', desc: 'Caddy 配置重载失败' },
  { value: 'cert.deployed', label: 'cert.deployed', desc: '证书续期并部署成功' },
]

const DEFAULT_EVENTS: WebhookEventName[] = [
  'cert.issue_failed',
  'cert.expiring_soon',
  'deploy.failed',
  'caddy.reload_failed',
]

const webhooks = ref<WebhookDTO[]>([])
const webhooksLoading = ref(false)
const webhookModalOpen = ref(false)
const editingWebhook = ref<WebhookDTO | null>(null)
const webhookSaving = ref(false)
const testingWebhookId = ref<number | null>(null)
const headersEditMode = ref<'kv' | 'json'>('kv')

const webhookForm = reactive({
  name: '',
  url: '',
  secret: '',
  enabled: true,
  events: [...DEFAULT_EVENTS] as string[],
  headerPairs: [] as { key: string; value: string }[],
  headersJson: '{}',
})

async function loadWebhooks() {
  webhooksLoading.value = true
  try {
    webhooks.value = await listWebhooks()
  } catch (err) {
    showToast('error', err instanceof Error ? err.message : '加载 Webhook 列表失败')
  } finally {
    webhooksLoading.value = false
  }
}

function openCreateWebhook() {
  editingWebhook.value = null
  headersEditMode.value = 'kv'
  Object.assign(webhookForm, {
    name: '',
    url: '',
    secret: '',
    enabled: true,
    events: [...DEFAULT_EVENTS],
    headerPairs: [],
    headersJson: '{}',
  })
  webhookModalOpen.value = true
}

function openEditWebhook(wh: WebhookDTO) {
  editingWebhook.value = wh
  headersEditMode.value = 'kv'
  Object.assign(webhookForm, {
    name: wh.name,
    url: wh.url,
    secret: '',
    enabled: wh.enabled,
    events: [...wh.events],
    headerPairs: [],
    headersJson: '{}',
  })
  webhookModalOpen.value = true
}

function addHeaderPair() {
  webhookForm.headerPairs.push({ key: '', value: '' })
}

function removeHeaderPair(idx: number) {
  webhookForm.headerPairs.splice(idx, 1)
}

function buildHeadersMap(): Record<string, string> | undefined {
  if (headersEditMode.value === 'json') {
    const raw = webhookForm.headersJson.trim()
    if (!raw || raw === '{}') return undefined
    const parsed = JSON.parse(raw) as Record<string, unknown>
    const out: Record<string, string> = {}
    for (const [k, v] of Object.entries(parsed)) {
      if (k.trim()) out[k.trim()] = String(v ?? '')
    }
    return Object.keys(out).length > 0 ? out : undefined
  }
  const out: Record<string, string> = {}
  for (const pair of webhookForm.headerPairs) {
    if (pair.key.trim()) {
      out[pair.key.trim()] = pair.value
    }
  }
  return Object.keys(out).length > 0 ? out : undefined
}

async function submitWebhook() {
  if (!webhookForm.name.trim() || !webhookForm.url.trim()) {
    showToast('warning', '请填写 Webhook 名称和 URL')
    return
  }

  let headers: Record<string, string> | undefined
  try {
    headers = buildHeadersMap()
  } catch {
    showToast('error', '自定义 Headers JSON 格式无效')
    return
  }

  webhookSaving.value = true
  try {
    if (editingWebhook.value) {
      await updateWebhook(editingWebhook.value.id, {
        name: webhookForm.name.trim(),
        url: webhookForm.url.trim(),
        headers,
        secret: webhookForm.secret.trim() ? webhookForm.secret.trim() : undefined,
        events: webhookForm.events,
        enabled: webhookForm.enabled,
      })
      showToast('success', 'Webhook 已更新')
    } else {
      await createWebhook({
        name: webhookForm.name.trim(),
        url: webhookForm.url.trim(),
        headers,
        secret: webhookForm.secret.trim() ? webhookForm.secret.trim() : undefined,
        events: webhookForm.events,
        enabled: webhookForm.enabled,
      })
      showToast('success', 'Webhook 创建成功')
    }
    webhookModalOpen.value = false
    await loadWebhooks()
  } catch (err) {
    showToast('error', err instanceof Error ? err.message : '保存 Webhook 失败')
  } finally {
    webhookSaving.value = false
  }
}

async function handleTestWebhook(wh: WebhookDTO) {
  testingWebhookId.value = wh.id
  try {
    const res = await testWebhook(wh.id)
    if (res.ok) {
      showToast('success', `Webhook「${wh.name}」测试发送成功 (HTTP ${res.status_code})`)
    } else {
      const detail = res.error || res.message
      showToast(
        'warning',
        detail
          ? `Webhook 测试失败 (HTTP ${res.status_code}): ${detail}`
          : `Webhook 返回异常状态码 HTTP ${res.status_code}`,
      )
    }
    await loadWebhooks()
  } catch (err) {
    showToast('error', err instanceof Error ? err.message : 'Webhook 测试发送失败')
  } finally {
    testingWebhookId.value = null
  }
}

// ============================================================================
// Admin Password
// ============================================================================
const pwdForm = reactive({
  current_password: '',
  new_password: '',
  confirm_password: '',
})
const pwdSaving = ref(false)

async function submitPasswordChange() {
  if (!pwdForm.current_password || !pwdForm.new_password) {
    showToast('warning', '请输入当前密码与新密码')
    return
  }
  if (pwdForm.new_password.length < 8) {
    showToast('warning', '新密码长度至少为 8 位')
    return
  }
  if (pwdForm.new_password !== pwdForm.confirm_password) {
    showToast('warning', '两次输入的新密码不一致')
    return
  }

  pwdSaving.value = true
  try {
    await changePassword({
      current_password: pwdForm.current_password,
      new_password: pwdForm.new_password,
    })
    pwdForm.current_password = ''
    pwdForm.new_password = ''
    pwdForm.confirm_password = ''
    showToast('success', '管理员密码已更新')
  } catch (err) {
    if (err instanceof ApiError && err.status === 401) {
      showToast('error', '当前密码不正确')
    } else {
      showToast('error', err instanceof Error ? err.message : '修改密码失败')
    }
  } finally {
    pwdSaving.value = false
  }
}

// ============================================================================
// Backup & Restore
// ============================================================================
const exportingBackup = ref(false)
const restoringBackup = ref(false)
const restoreFile = ref<File | null>(null)
const restoreResult = ref<RestoreResult | null>(null)
const restoreConfirmOpen = ref(false)

async function handleExportBackup() {
  exportingBackup.value = true
  try {
    await exportBackup()
    showToast('success', '完整备份包已开始下载')
  } catch (err) {
    showToast('error', err instanceof Error ? err.message : '导出备份失败')
  } finally {
    exportingBackup.value = false
  }
}

function handleRestoreFileSelect(e: Event) {
  const input = e.target as HTMLInputElement
  restoreFile.value = input.files?.[0] || null
}

function requestRestore() {
  if (!restoreFile.value) {
    showToast('warning', '请先选择 .tar.gz 备份文件')
    return
  }
  restoreConfirmOpen.value = true
}

async function confirmRestore() {
  if (!restoreFile.value) return
  restoringBackup.value = true
  try {
    const res = await restoreBackup(restoreFile.value)
    restoreResult.value = res
    restoreConfirmOpen.value = false
    if (res.relogin_required) {
      clearAuthState()
      showToast('success', res.message || '备份恢复成功，请使用备份中的管理员密码重新登录')
      await router.replace('/login')
    } else {
      showToast('success', res.message || '备份恢复完成')
    }
  } catch (err) {
    showToast('error', err instanceof Error ? err.message : '备份恢复失败')
  } finally {
    restoringBackup.value = false
  }
}

// ============================================================================
// Delete Confirm
// ============================================================================
const deleteConfirmOpen = ref(false)
const deleteTargetWebhook = ref<WebhookDTO | null>(null)
const deleteLoading = ref(false)

function requestDeleteWebhook(wh: WebhookDTO) {
  deleteTargetWebhook.value = wh
  deleteConfirmOpen.value = true
}

async function confirmDeleteWebhook() {
  if (!deleteTargetWebhook.value) return
  deleteLoading.value = true
  try {
    await deleteWebhook(deleteTargetWebhook.value.id)
    showToast('success', 'Webhook 已删除')
    deleteConfirmOpen.value = false
    await loadWebhooks()
  } catch (err) {
    showToast('error', err instanceof Error ? err.message : '删除失败')
  } finally {
    deleteLoading.value = false
  }
}

onMounted(() => {
  void loadSettings()
  void loadWebhooks()
})
</script>

<template>
  <div class="space-y-6">
    <div>
      <h1 class="text-2xl font-bold tracking-tight text-slate-900">系统设置</h1>
      <p class="mt-1 text-sm text-slate-500">
        配置每日续期巡检计划、日志清理策略、Webhook 告警通知、管理员密码及备份迁移
      </p>
    </div>

    <div class="grid gap-6 lg:grid-cols-2">
      <!-- Scheduler & Log Retention -->
      <section class="rounded-xl border border-slate-200 bg-white p-6 shadow-sm">
        <div class="mb-5 flex items-center gap-2.5">
          <div class="flex h-9 w-9 items-center justify-center rounded-lg bg-indigo-50 text-indigo-600">
            <Clock class="h-5 w-5" />
          </div>
          <div>
            <h2 class="text-base font-semibold text-slate-900">调度与日志保留策略</h2>
            <p class="text-xs text-slate-500">修改巡检时刻将立即热重载调度器</p>
          </div>
        </div>

        <form class="space-y-4" @submit.prevent="saveSettings">
          <div class="grid gap-4 sm:grid-cols-2">
            <div>
              <label class="mb-1 block text-xs font-medium text-slate-700">每日巡检时刻 (HH:MM)</label>
              <input
                v-model="settingsForm.inspect_time"
                type="time"
                class="w-full rounded-lg border border-slate-300 px-3 py-2 font-mono text-sm tabular-nums focus:border-indigo-500 focus:outline-none"
              />
            </div>
            <div>
              <label class="mb-1 block text-xs font-medium text-slate-700">默认提前续期天数</label>
              <input
                v-model.number="settingsForm.renew_before_days"
                type="number"
                min="1"
                max="90"
                class="w-full rounded-lg border border-slate-300 px-3 py-2 text-sm tabular-nums focus:border-indigo-500 focus:outline-none"
              />
            </div>
            <div>
              <label class="mb-1 block text-xs font-medium text-slate-700">临期告警阈值（天）</label>
              <input
                v-model.number="settingsForm.expiring_warn_days"
                type="number"
                min="1"
                max="60"
                class="w-full rounded-lg border border-slate-300 px-3 py-2 text-sm tabular-nums focus:border-indigo-500 focus:outline-none"
              />
            </div>
            <div>
              <label class="mb-1 block text-xs font-medium text-slate-700">日志保留天数</label>
              <input
                v-model.number="settingsForm.log_retention_days"
                type="number"
                min="1"
                max="3650"
                class="w-full rounded-lg border border-slate-300 px-3 py-2 text-sm tabular-nums focus:border-indigo-500 focus:outline-none"
              />
            </div>
            <div class="sm:col-span-2">
              <label class="mb-1 block text-xs font-medium text-slate-700">单表最大日志保留行数</label>
              <input
                v-model.number="settingsForm.log_max_rows"
                type="number"
                min="100"
                max="1000000"
                class="w-full rounded-lg border border-slate-300 px-3 py-2 text-sm tabular-nums focus:border-indigo-500 focus:outline-none"
              />
            </div>
          </div>

          <div class="flex flex-wrap items-center justify-between gap-3 border-t border-slate-100 pt-4">
            <button
              type="button"
              :disabled="pruning"
              class="rounded-lg border border-slate-300 bg-white px-3.5 py-2 text-xs font-medium text-slate-700 hover:bg-slate-50 disabled:opacity-50"
              @click="handlePruneLogs"
            >
              {{ pruning ? '清理中...' : '手动清理过期日志' }}
            </button>

            <button
              type="submit"
              :disabled="settingsSaving || settingsLoading"
              class="rounded-lg bg-indigo-600 px-4 py-2 text-sm font-semibold text-white hover:bg-indigo-700 disabled:opacity-50"
            >
              {{ settingsSaving ? '保存中...' : '保存策略' }}
            </button>
          </div>
        </form>

        <div
          v-if="pruneResult"
          class="mt-4 rounded-lg border border-emerald-200 bg-emerald-50 p-3 text-xs text-emerald-800 tabular-nums"
        >
          清理完成：签发任务 {{ pruneResult.cert_jobs_deleted }} 条 · 部署日志
          {{ pruneResult.deploy_logs_deleted }} 条 · 审计事件 {{ pruneResult.audit_events_deleted }} 条
          （共 {{ pruneResult.total_deleted }} 条，VACUUM: {{ pruneResult.vacuum_ran ? '已执行' : '未触发' }}）
        </div>
      </section>

      <!-- Admin Password Change -->
      <section class="rounded-xl border border-slate-200 bg-white p-6 shadow-sm">
        <div class="mb-5 flex items-center gap-2.5">
          <div class="flex h-9 w-9 items-center justify-center rounded-lg bg-sky-50 text-sky-600">
            <KeyRound class="h-5 w-5" />
          </div>
          <div>
            <h2 class="text-base font-semibold text-slate-900">管理员密码修改</h2>
            <p class="text-xs text-slate-500">使用 Argon2id 哈希存储，修改后其他会话自动失效</p>
          </div>
        </div>

        <form class="space-y-4" @submit.prevent="submitPasswordChange">
          <div>
            <label class="mb-1 block text-xs font-medium text-slate-700">当前密码</label>
            <input
              v-model="pwdForm.current_password"
              type="password"
              autocomplete="current-password"
              class="w-full rounded-lg border border-slate-300 px-3 py-2 text-sm focus:border-indigo-500 focus:outline-none"
            />
          </div>
          <div>
            <label class="mb-1 block text-xs font-medium text-slate-700">新密码（至少 8 位）</label>
            <input
              v-model="pwdForm.new_password"
              type="password"
              autocomplete="new-password"
              class="w-full rounded-lg border border-slate-300 px-3 py-2 text-sm focus:border-indigo-500 focus:outline-none"
            />
          </div>
          <div>
            <label class="mb-1 block text-xs font-medium text-slate-700">确认新密码</label>
            <input
              v-model="pwdForm.confirm_password"
              type="password"
              autocomplete="new-password"
              class="w-full rounded-lg border border-slate-300 px-3 py-2 text-sm focus:border-indigo-500 focus:outline-none"
            />
          </div>

          <div class="flex justify-end border-t border-slate-100 pt-4">
            <button
              type="submit"
              :disabled="pwdSaving"
              class="rounded-lg bg-slate-900 px-4 py-2 text-sm font-semibold text-white hover:bg-slate-800 disabled:opacity-50"
            >
              {{ pwdSaving ? '提交中...' : '更新密码' }}
            </button>
          </div>
        </form>
      </section>
    </div>

    <!-- Webhooks Manager -->
    <section class="rounded-xl border border-slate-200 bg-white shadow-sm">
      <div class="flex flex-wrap items-center justify-between gap-3 border-b border-slate-200 px-6 py-4">
        <div class="flex items-center gap-2.5">
          <div class="flex h-9 w-9 items-center justify-center rounded-lg bg-amber-50 text-amber-600">
            <Bell class="h-5 w-5" />
          </div>
          <div>
            <h2 class="text-base font-semibold text-slate-900">通用 Webhook 告警配置</h2>
            <p class="text-xs text-slate-500">支持加密请求头、HMAC-SHA256 签名与 5 类标准运维事件</p>
          </div>
        </div>
        <button
          type="button"
          class="inline-flex items-center gap-1.5 rounded-lg bg-indigo-600 px-3.5 py-2 text-xs font-semibold text-white hover:bg-indigo-700"
          @click="openCreateWebhook"
        >
          <Plus class="h-4 w-4" />
          新增 Webhook
        </button>
      </div>

      <div v-if="webhooksLoading && webhooks.length === 0" class="p-8 text-center text-sm text-slate-500">
        正在加载 Webhook 配置...
      </div>
      <div v-else-if="webhooks.length === 0" class="p-10 text-center text-sm text-slate-500">
        尚未配置 Webhook 端点，点击右上角新增告警通知目标
      </div>
      <div v-else class="divide-y divide-slate-100">
        <div
          v-for="wh in webhooks"
          :key="wh.id"
          class="flex flex-col gap-3 px-6 py-4 lg:flex-row lg:items-center lg:justify-between"
        >
          <div class="min-w-0 flex-1 space-y-1.5">
            <div class="flex flex-wrap items-center gap-2">
              <span class="text-sm font-semibold text-slate-900">{{ wh.name }}</span>
              <StatusBadge :status="wh.enabled ? 'active' : 'stopped'" :label="wh.enabled ? '已启用' : '已停用'" />
              <span v-if="wh.has_secret" class="rounded bg-indigo-50 px-2 py-0.5 text-[11px] font-medium text-indigo-700">
                HMAC 签名
              </span>
              <span
                v-if="wh.header_keys && wh.header_keys.length > 0"
                class="rounded bg-slate-100 px-2 py-0.5 font-mono text-[11px] text-slate-600"
              >
                Headers: {{ wh.header_keys.join(', ') }}
              </span>
            </div>
            <div class="truncate font-mono text-xs text-slate-500">{{ wh.url }}</div>
            <div class="flex flex-wrap gap-1.5 pt-0.5">
              <span
                v-for="ev in wh.events"
                :key="ev"
                class="rounded bg-slate-100 px-2 py-0.5 font-mono text-[11px] text-slate-700"
              >
                {{ ev }}
              </span>
            </div>
            <div v-if="wh.last_triggered_at || wh.last_error" class="text-xs text-slate-500 tabular-nums">
              上次触发: {{ formatDateTime(wh.last_triggered_at) }}
              <span v-if="wh.last_status_code" class="ml-2 font-mono">HTTP {{ wh.last_status_code }}</span>
              <span v-if="wh.last_error" class="ml-2 text-rose-600">错误: {{ wh.last_error }}</span>
            </div>
          </div>

          <div class="flex shrink-0 flex-wrap items-center gap-2">
            <button
              type="button"
              :disabled="testingWebhookId === wh.id"
              class="inline-flex items-center gap-1 rounded-lg border border-indigo-200 bg-indigo-50/70 px-2.5 py-1.5 text-xs font-medium text-indigo-700 hover:bg-indigo-100 disabled:opacity-50"
              @click="handleTestWebhook(wh)"
            >
              <Send class="h-3.5 w-3.5" />
              {{ testingWebhookId === wh.id ? '发送中...' : '测试发送' }}
            </button>
            <button
              type="button"
              class="inline-flex items-center gap-1 rounded-lg border border-slate-200 px-2.5 py-1.5 text-xs font-medium text-slate-700 hover:bg-slate-50"
              @click="openEditWebhook(wh)"
            >
              <Edit3 class="h-3.5 w-3.5" />
              编辑
            </button>
            <button
              type="button"
              class="inline-flex items-center gap-1 rounded-lg border border-rose-200 px-2.5 py-1.5 text-xs font-medium text-rose-600 hover:bg-rose-50"
              @click="requestDeleteWebhook(wh)"
            >
              <Trash2 class="h-3.5 w-3.5" />
              删除
            </button>
          </div>
        </div>
      </div>
    </section>

    <!-- Backup & Restore -->
    <section class="rounded-xl border border-slate-200 bg-white p-6 shadow-sm">
      <div class="mb-5 flex items-center gap-2.5">
        <div class="flex h-9 w-9 items-center justify-center rounded-lg bg-emerald-50 text-emerald-600">
          <HardDriveDownload class="h-5 w-5" />
        </div>
        <div>
          <h2 class="text-base font-semibold text-slate-900">一键完整备份与恢复</h2>
          <p class="text-xs text-slate-500">
            导出包包含一致性 SQLite 快照（已清除会话）、主加密密钥、CA 密钥与所有已签发证书
          </p>
        </div>
      </div>

      <div class="grid gap-6 md:grid-cols-2">
        <div class="rounded-xl border border-slate-200 bg-slate-50/70 p-4">
          <h3 class="text-sm font-semibold text-slate-900">导出备份包</h3>
          <p class="mt-1 text-xs leading-relaxed text-slate-500">
            生成完整 <code>.tar.gz</code> 归档（含 SHA-256 校验清单），可用于跨主机迁移或灾备还原。
          </p>
          <button
            type="button"
            :disabled="exportingBackup"
            class="mt-4 inline-flex items-center gap-2 rounded-lg bg-emerald-600 px-4 py-2 text-sm font-semibold text-white shadow-sm hover:bg-emerald-700 disabled:opacity-50"
            @click="handleExportBackup"
          >
            <Download class="h-4 w-4" />
            {{ exportingBackup ? '正在打包...' : '一键导出 .tar.gz 备份' }}
          </button>
        </div>

        <div class="rounded-xl border border-slate-200 bg-slate-50/70 p-4">
          <h3 class="text-sm font-semibold text-slate-900">上传并恢复备份</h3>
          <p class="mt-1 text-xs leading-relaxed text-slate-500">
            恢复前将自动校验归档安全性与主密钥一致性，原数据备份至 <code>pre_restore_*</code>，恢复后需使用备份中的管理员密码重新登录。
          </p>
          <div class="mt-3 flex flex-wrap items-center gap-2.5">
            <input
              type="file"
              accept=".tar.gz,.tgz,application/gzip"
              class="block flex-1 text-xs text-slate-600 file:mr-3 file:rounded-lg file:border-0 file:bg-white file:px-3 file:py-1.5 file:text-xs file:font-semibold file:text-slate-700 file:shadow-sm hover:file:bg-slate-100"
              @change="handleRestoreFileSelect"
            />
            <button
              type="button"
              :disabled="!restoreFile || restoringBackup"
              class="inline-flex items-center gap-1.5 rounded-lg bg-rose-600 px-4 py-2 text-xs font-semibold text-white hover:bg-rose-700 disabled:opacity-50"
              @click="requestRestore"
            >
              <Upload class="h-3.5 w-3.5" />
              {{ restoringBackup ? '恢复中...' : '执行恢复' }}
            </button>
          </div>
          <div v-if="restoreResult" class="mt-3 rounded-lg bg-emerald-50 p-2.5 text-xs text-emerald-800">
            {{ restoreResult.message }}
          </div>
        </div>
      </div>
    </section>

    <!-- Create / Edit Webhook Modal -->
    <ModalDialog
      :open="webhookModalOpen"
      :title="editingWebhook ? '编辑 Webhook' : '新增 Webhook'"
      subtitle="编辑时 Headers 与 HMAC Secret 留空则保持原加密值不变"
      max-width="xl"
      @close="webhookModalOpen = false"
    >
      <div class="space-y-4">
        <div class="grid gap-4 sm:grid-cols-2">
          <div>
            <label class="mb-1 block text-xs font-medium text-slate-700">名称 *</label>
            <input
              v-model="webhookForm.name"
              type="text"
              placeholder="例如：飞书运维群告警"
              class="w-full rounded-lg border border-slate-300 px-3 py-2 text-sm focus:border-indigo-500 focus:outline-none"
            />
          </div>
          <div class="flex items-end pb-2">
            <label class="flex cursor-pointer items-center gap-2 text-sm text-slate-700">
              <input v-model="webhookForm.enabled" type="checkbox" class="rounded border-slate-300 text-indigo-600" />
              启用此 Webhook
            </label>
          </div>
        </div>

        <div>
          <label class="mb-1 block text-xs font-medium text-slate-700">接收端点 URL *</label>
          <input
            v-model="webhookForm.url"
            type="url"
            placeholder="https://hooks.example.com/notify"
            class="w-full rounded-lg border border-slate-300 px-3 py-2 font-mono text-xs focus:border-indigo-500 focus:outline-none"
          />
        </div>

        <div>
          <label class="mb-1 block text-xs font-medium text-slate-700">
            HMAC-SHA256 签名密钥 {{ editingWebhook ? '（留空保持原密钥）' : '（可选）' }}
          </label>
          <input
            v-model="webhookForm.secret"
            type="password"
            placeholder="配置后将在请求头附带 X-Webhook-Signature: sha256=..."
            class="w-full rounded-lg border border-slate-300 px-3 py-2 font-mono text-xs focus:border-indigo-500 focus:outline-none"
          />
        </div>

        <div>
          <div class="mb-1.5 flex items-center justify-between">
            <label class="text-xs font-medium text-slate-700">
              自定义 HTTP Headers {{ editingWebhook ? '（留空保持原有 Headers）' : '（可选）' }}
            </label>
            <div class="flex gap-1 rounded bg-slate-100 p-0.5 text-[11px]">
              <button
                type="button"
                class="rounded px-2 py-0.5"
                :class="headersEditMode === 'kv' ? 'bg-white font-semibold shadow-sm' : 'text-slate-600'"
                @click="headersEditMode = 'kv'"
              >
                键值表单
              </button>
              <button
                type="button"
                class="rounded px-2 py-0.5"
                :class="headersEditMode === 'json' ? 'bg-white font-semibold shadow-sm' : 'text-slate-600'"
                @click="headersEditMode = 'json'"
              >
                JSON 模式
              </button>
            </div>
          </div>

          <div v-if="headersEditMode === 'kv'" class="space-y-2 rounded-lg border border-slate-200 bg-slate-50 p-3">
            <div v-for="(pair, idx) in webhookForm.headerPairs" :key="idx" class="flex gap-2">
              <input
                v-model="pair.key"
                type="text"
                placeholder="Header Name (如 Authorization)"
                class="w-1/2 rounded border border-slate-300 bg-white px-2.5 py-1.5 font-mono text-xs"
              />
              <input
                v-model="pair.value"
                type="text"
                placeholder="Header Value"
                class="w-1/2 rounded border border-slate-300 bg-white px-2.5 py-1.5 font-mono text-xs"
              />
              <button
                type="button"
                class="rounded px-2 text-xs text-rose-600 hover:bg-rose-50"
                @click="removeHeaderPair(idx)"
              >
                移除
              </button>
            </div>
            <button
              type="button"
              class="text-xs font-medium text-indigo-600 hover:text-indigo-700"
              @click="addHeaderPair"
            >
              + 添加 Header
            </button>
          </div>
          <textarea
            v-else
            v-model="webhookForm.headersJson"
            rows="3"
            placeholder='{"Authorization": "Bearer xxx"}'
            class="w-full rounded-lg border border-slate-300 px-3 py-2 font-mono text-xs focus:border-indigo-500 focus:outline-none"
          />
        </div>

        <div>
          <label class="mb-2 block text-xs font-medium text-slate-700">订阅事件</label>
          <div class="grid gap-2 sm:grid-cols-2">
            <label
              v-for="ev in ALL_WEBHOOK_EVENTS"
              :key="ev.value"
              class="flex cursor-pointer items-start gap-2 rounded-lg border border-slate-200 p-2.5 hover:bg-slate-50"
            >
              <input
                v-model="webhookForm.events"
                type="checkbox"
                :value="ev.value"
                class="mt-0.5 rounded border-slate-300 text-indigo-600"
              />
              <div>
                <div class="font-mono text-xs font-medium text-slate-800">{{ ev.label }}</div>
                <div class="text-[11px] text-slate-500">{{ ev.desc }}</div>
              </div>
            </label>
          </div>
        </div>
      </div>

      <template #footer>
        <button
          type="button"
          class="rounded-lg border border-slate-300 bg-white px-4 py-2 text-sm font-medium text-slate-700 hover:bg-slate-50"
          @click="webhookModalOpen = false"
        >
          取消
        </button>
        <button
          type="button"
          :disabled="webhookSaving"
          class="rounded-lg bg-indigo-600 px-4 py-2 text-sm font-semibold text-white hover:bg-indigo-700 disabled:opacity-50"
          @click="submitWebhook"
        >
          {{ webhookSaving ? '保存中...' : '保存 Webhook' }}
        </button>
      </template>
    </ModalDialog>

    <!-- Confirm Restore -->
    <ConfirmDialog
      :open="restoreConfirmOpen"
      title="确认执行备份恢复"
      :message="`即将从备份文件「${restoreFile?.name || ''}」全量恢复数据库、主密钥与证书。\n当前数据将被移至 pre_restore_* 目录，恢复后需重新登录。确定继续吗？`"
      confirm-text="确认恢复"
      danger
      :loading="restoringBackup"
      @confirm="confirmRestore"
      @cancel="restoreConfirmOpen = false"
    />

    <!-- Confirm Delete Webhook -->
    <ConfirmDialog
      :open="deleteConfirmOpen"
      title="删除 Webhook"
      :message="`确定要删除 Webhook「${deleteTargetWebhook?.name || ''}」吗？`"
      confirm-text="确认删除"
      danger
      :loading="deleteLoading"
      @confirm="confirmDeleteWebhook"
      @cancel="deleteConfirmOpen = false"
    />
  </div>
</template>
