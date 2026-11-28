<script setup lang="ts">
import { computed, onMounted, ref } from 'vue'
import { useRouter } from 'vue-router'
import {
  Activity,
  AlertTriangle,
  ArrowRight,
  CheckCircle2,
  ChevronDown,
  ChevronUp,
  Circle,
  ExternalLink,
  RefreshCw,
  Rocket,
  Server,
  ShieldCheck,
} from 'lucide-vue-next'
import { getDashboard } from '@/api/dashboard'
import StatusBadge from '@/components/ui/StatusBadge.vue'
import { formatDateTime, formatRelativeTime } from '@/utils/format'
import type { AuditEvent, ChecklistItem, DashboardResponse } from '@/types/api'

const router = useRouter()

const loading = ref(false)
const errorMsg = ref('')
const data = ref<DashboardResponse | null>(null)
const levelFilter = ref<'all' | 'info' | 'warn' | 'error'>('all')

const CHECKLIST_STORAGE_KEY = 'ssl_center_checklist_collapsed'
const checklistCollapsed = ref(localStorage.getItem(CHECKLIST_STORAGE_KEY) === 'true')
const checklistUserToggled = ref(false)

function toggleChecklist() {
  checklistUserToggled.value = true
  checklistCollapsed.value = !checklistCollapsed.value
  localStorage.setItem(CHECKLIST_STORAGE_KEY, String(checklistCollapsed.value))
}

async function loadDashboard() {
  loading.value = true
  errorMsg.value = ''
  try {
    const res = await getDashboard()
    const items = res.checklist || []
    const allDone = items.length > 0 && items.every((item) => item.done)
    if (!checklistUserToggled.value) {
      checklistCollapsed.value = allDone
        ? true
        : localStorage.getItem(CHECKLIST_STORAGE_KEY) === 'true'
    }
    data.value = res
  } catch (err) {
    errorMsg.value = err instanceof Error ? err.message : '加载概览数据失败'
  } finally {
    loading.value = false
  }
}

onMounted(() => {
  void loadDashboard()
})

const checklistItems = computed<ChecklistItem[]>(() => {
  return data.value?.checklist ? [...data.value.checklist] : []
})

const completedChecklistCount = computed(() =>
  checklistItems.value.filter((item) => item.done).length,
)

const certIssueCount = computed(() => {
  if (!data.value) return 0
  const s = data.value.cert_stats
  return s.expired + s.error
})

const deploySuccessRate = computed<number | null>(() => {
  if (!data.value || data.value.deployment_stats.total === 0) return null
  return Math.round(
    (data.value.deployment_stats.success / data.value.deployment_stats.total) * 100,
  )
})

const filteredEvents = computed(() => {
  const events = data.value?.recent_events || []
  if (levelFilter.value === 'all') return events
  return events.filter((e) => e.level === levelFilter.value)
})

const levelCounts = computed(() => {
  const events = data.value?.recent_events || []
  return {
    all: events.length,
    info: events.filter((e) => e.level === 'info').length,
    warn: events.filter((e) => e.level === 'warn').length,
    error: events.filter((e) => e.level === 'error').length,
  }
})

const EVENT_TYPE_LABELS: Record<string, string> = {
  'auth.login': '管理员登录',
  'auth.login_failed': '登录失败',
  'auth.logout': '退出登录',
  'auth.password_changed': '修改密码',
  'ca.created': '创建 CA 账户',
  'ca.updated': '更新 CA 账户',
  'ca.deleted': '删除 CA 账户',
  'ca.default_set': '设为默认 CA',
  'ca.key_exported': '导出 CA 密钥',
  'dns.created': '创建 DNS 凭据',
  'dns.updated': '更新 DNS 凭据',
  'dns.deleted': '删除 DNS 凭据',
  'cert.created': '创建证书',
  'cert.updated': '更新证书',
  'cert.deleted': '删除证书',
  'cert.issued': '签发成功',
  'cert.issue_failed': '签发失败',
  'cert.renewed': '续期成功',
  'cert.key_exported': '导出证书私钥',
  'cert.bundle_downloaded': '下载证书包',
  'host.created': '添加主机',
  'host.updated': '更新主机',
  'host.deleted': '删除主机',
  'host.host_key_reset': '重置 SSH 指纹',
  'host.host_key_mismatch': 'SSH 指纹异常',
  'deployment.created': '创建部署目标',
  'deployment.updated': '更新部署目标',
  'deployment.deleted': '删除部署目标',
  'caddy.published': '发布 Caddyfile',
  'caddy.rolled_back': '回滚 Caddyfile',
  'caddy.reloaded': '重载 Caddy',
  'caddy.reload_failed': 'Caddy 重载失败',
  'webhook.created': '创建 Webhook',
  'webhook.updated': '更新 Webhook',
  'webhook.deleted': '删除 Webhook',
  'settings.updated': '更新系统设置',
  'settings.logs_pruned': '清理历史日志',
  'backup.exported': '导出备份',
  'backup.restored': '恢复备份',
}

function formatEventType(ev: AuditEvent): string {
  return EVENT_TYPE_LABELS[ev.event_type] || ev.event_type
}

function getAuditTargetRoute(ev: AuditEvent) {
  if (!ev.target_id) {
    if (ev.target_type === 'ca_account') return { path: '/credentials', query: { tab: 'ca' } }
    if (ev.target_type === 'dns_credential') return { path: '/credentials', query: { tab: 'dns' } }
    if (ev.target_type === 'settings' || ev.target_type === 'webhook') return { path: '/settings' }
    return null
  }
  if (ev.target_type === 'certificate') {
    return { path: '/certificates', query: { certId: String(ev.target_id) } }
  }
  if (ev.target_type === 'host') {
    return { path: '/hosts', query: { hostId: String(ev.target_id) } }
  }
  if (ev.target_type === 'deployment') {
    try {
      const meta = ev.meta_json ? JSON.parse(ev.meta_json) : null
      if (meta?.certificate_id) {
        return { path: '/certificates', query: { certId: String(meta.certificate_id), tab: 'deployments' } }
      }
      if (meta?.host_id) {
        return { path: '/hosts', query: { hostId: String(meta.host_id), tab: 'deployments' } }
      }
    } catch {
      return { path: '/certificates' }
    }
  }
  return null
}

function handleAuditClick(ev: AuditEvent) {
  const target = getAuditTargetRoute(ev)
  if (target) {
    void router.push(target)
  }
}
</script>

<template>
  <div class="space-y-6">
    <!-- Header -->
    <div class="flex flex-wrap items-center justify-between gap-4">
      <div>
        <h1 class="text-2xl font-bold tracking-tight text-slate-900">运维概览</h1>
        <p class="mt-1 text-sm text-slate-500">
          全局证书健康状态、主机连通性与部署同步实时总览
        </p>
      </div>
      <button
        type="button"
        class="inline-flex items-center gap-2 rounded-lg border border-slate-200 bg-white px-3.5 py-2 text-sm font-medium text-slate-700 shadow-sm transition hover:bg-slate-50"
        :disabled="loading"
        @click="loadDashboard"
      >
        <RefreshCw class="h-4 w-4" :class="loading ? 'animate-spin text-indigo-600' : 'text-slate-400'" />
        刷新数据
      </button>
    </div>

    <div
      v-if="errorMsg"
      class="rounded-xl border border-rose-200 bg-rose-50 px-4 py-3 text-sm text-rose-700"
    >
      {{ errorMsg }}
    </div>

    <!-- Collapsible Onboarding Checklist -->
    <section
      v-if="checklistItems.length > 0"
      class="overflow-hidden rounded-xl border border-indigo-100 bg-white shadow-sm"
    >
      <button
        type="button"
        class="flex w-full items-center justify-between bg-gradient-to-r from-indigo-50/80 via-white to-white px-5 py-3.5 text-left transition hover:bg-indigo-50/40"
        @click="toggleChecklist"
      >
        <div class="flex items-center gap-3">
          <span class="flex h-8 w-8 items-center justify-center rounded-lg bg-indigo-600 text-white">
            <Rocket class="h-4 w-4" />
          </span>
          <div>
            <div class="flex items-center gap-2">
              <h2 class="text-sm font-semibold text-slate-900">配置引导 Checklist</h2>
              <span
                class="rounded-full px-2 py-0.5 text-xs font-semibold tabular-nums"
                :class="
                  completedChecklistCount === checklistItems.length
                    ? 'bg-emerald-100 text-emerald-700'
                    : 'bg-indigo-100 text-indigo-700'
                "
              >
                {{ completedChecklistCount }}/{{ checklistItems.length }}
              </span>
            </div>
            <p class="text-xs text-slate-500">按顺序完成 CA、DNS、主机、证书与部署目标配置</p>
          </div>
        </div>
        <div class="flex items-center gap-2 text-xs font-medium text-slate-500">
          <span>{{ checklistCollapsed ? '展开' : '收起' }}</span>
          <ChevronDown v-if="checklistCollapsed" class="h-4 w-4" />
          <ChevronUp v-else class="h-4 w-4" />
        </div>
      </button>

      <div v-if="!checklistCollapsed" class="grid gap-3 border-t border-slate-100 p-4 sm:grid-cols-2 lg:grid-cols-5">
        <router-link
          v-for="(item, index) in checklistItems"
          :key="item.key"
          :to="item.href"
          class="group flex flex-col justify-between rounded-xl border p-3.5 transition"
          :class="
            item.done
              ? 'border-emerald-200 bg-emerald-50/40 hover:border-emerald-300'
              : 'border-slate-200 bg-slate-50/50 hover:border-indigo-300 hover:bg-indigo-50/30'
          "
        >
          <div class="flex items-center justify-between">
            <span class="text-xs font-semibold text-slate-400 tabular-nums">步骤 {{ index + 1 }}</span>
            <CheckCircle2 v-if="item.done" class="h-4 w-4 text-emerald-600" />
            <Circle v-else class="h-4 w-4 text-slate-300 group-hover:text-indigo-500" />
          </div>
          <div class="mt-2.5 flex items-center justify-between gap-2">
            <span class="text-sm font-medium text-slate-800">{{ item.title }}</span>
            <ArrowRight class="h-3.5 w-3.5 shrink-0 text-slate-400 transition group-hover:translate-x-0.5 group-hover:text-indigo-600" />
          </div>
        </router-link>
      </div>
    </section>

    <!-- Summary Cards -->
    <div v-if="data" class="grid gap-4 sm:grid-cols-2 xl:grid-cols-4">
      <!-- Certificates -->
      <router-link
        to="/certificates"
        class="rounded-xl border border-slate-200 bg-white p-5 shadow-sm transition hover:border-indigo-200"
      >
        <div class="flex items-center justify-between">
          <span class="text-sm font-medium text-slate-500">证书健康</span>
          <div class="flex h-9 w-9 items-center justify-center rounded-lg bg-indigo-50 text-indigo-600">
            <ShieldCheck class="h-5 w-5" />
          </div>
        </div>
        <div class="mt-3 flex items-baseline gap-2">
          <span class="text-3xl font-bold text-slate-900 tabular-nums">{{ data.cert_stats.total }}</span>
          <span class="text-xs text-slate-500">张证书</span>
        </div>
        <div class="mt-4 flex flex-wrap gap-2 text-xs tabular-nums">
          <span class="rounded-md bg-emerald-50 px-2 py-0.5 font-medium text-emerald-700">
            有效 {{ data.cert_stats.valid }}
          </span>
          <span class="rounded-md bg-amber-50 px-2 py-0.5 font-medium text-amber-700">
            临期 {{ data.cert_stats.expiring }}
          </span>
          <span
            class="rounded-md px-2 py-0.5 font-medium"
            :class="certIssueCount > 0 ? 'bg-rose-50 text-rose-700' : 'bg-slate-100 text-slate-600'"
          >
            异常 {{ certIssueCount }}
          </span>
        </div>
      </router-link>

      <!-- Hosts -->
      <router-link
        to="/hosts"
        class="rounded-xl border border-slate-200 bg-white p-5 shadow-sm transition hover:border-indigo-200"
      >
        <div class="flex items-center justify-between">
          <span class="text-sm font-medium text-slate-500">主机资产</span>
          <div class="flex h-9 w-9 items-center justify-center rounded-lg bg-sky-50 text-sky-600">
            <Server class="h-5 w-5" />
          </div>
        </div>
        <div class="mt-3 flex items-baseline gap-2">
          <span class="text-3xl font-bold text-slate-900 tabular-nums">{{ data.host_stats.total }}</span>
          <span class="text-xs text-slate-500">台主机</span>
        </div>
        <div class="mt-4 flex flex-wrap gap-2 text-xs tabular-nums">
          <span class="rounded-md bg-emerald-50 px-2 py-0.5 font-medium text-emerald-700">
            在线 {{ data.host_stats.reachable }}
          </span>
          <span class="rounded-md bg-indigo-50 px-2 py-0.5 font-medium text-indigo-700">
            Caddy 运行 {{ data.host_stats.caddy_running }}
          </span>
          <span
            v-if="data.host_stats.unreachable > 0"
            class="rounded-md bg-rose-50 px-2 py-0.5 font-medium text-rose-700"
          >
            离线 {{ data.host_stats.unreachable }}
          </span>
        </div>
      </router-link>

      <!-- Deployments -->
      <router-link
        to="/certificates"
        class="rounded-xl border border-slate-200 bg-white p-5 shadow-sm transition hover:border-indigo-200"
      >
        <div class="flex items-center justify-between">
          <span class="text-sm font-medium text-slate-500">部署目标</span>
          <div class="flex h-9 w-9 items-center justify-center rounded-lg bg-emerald-50 text-emerald-600">
            <Activity class="h-5 w-5" />
          </div>
        </div>
        <div class="mt-3 flex items-baseline gap-2">
          <span class="text-3xl font-bold text-slate-900 tabular-nums">{{ data.deployment_stats.total }}</span>
          <span class="text-xs text-slate-500">个绑定目标</span>
        </div>
        <div class="mt-4 flex flex-wrap gap-2 text-xs tabular-nums">
          <span class="rounded-md bg-emerald-50 px-2 py-0.5 font-medium text-emerald-700">
            成功 {{ data.deployment_stats.success }}
          </span>
          <span
            class="rounded-md px-2 py-0.5 font-medium"
            :class="
              data.deployment_stats.failed > 0
                ? 'bg-rose-50 text-rose-700'
                : 'bg-slate-100 text-slate-600'
            "
          >
            失败 {{ data.deployment_stats.failed }}
          </span>
          <span class="rounded-md bg-slate-100 px-2 py-0.5 font-medium text-slate-600">
            待推送 {{ data.deployment_stats.pending }}
          </span>
        </div>
      </router-link>

      <!-- Sync Overview -->
      <div class="rounded-xl border border-slate-200 bg-white p-5 shadow-sm">
        <div class="flex items-center justify-between">
          <span class="text-sm font-medium text-slate-500">部署同步率</span>
          <div
            class="flex h-9 w-9 items-center justify-center rounded-lg"
            :class="
              data.deployment_stats.failed > 0
                ? 'bg-amber-50 text-amber-600'
                : 'bg-emerald-50 text-emerald-600'
            "
          >
            <AlertTriangle v-if="data.deployment_stats.failed > 0" class="h-5 w-5" />
            <CheckCircle2 v-else class="h-5 w-5" />
          </div>
        </div>
        <div class="mt-3 flex items-baseline gap-2">
          <span class="text-3xl font-bold text-slate-900 tabular-nums">
            {{ deploySuccessRate === null ? '—' : `${deploySuccessRate}%` }}
          </span>
          <span class="text-xs text-slate-500">
            {{ deploySuccessRate === null ? '暂无部署目标' : '目标已同步' }}
          </span>
        </div>
        <div class="mt-4">
          <div class="h-2 w-full overflow-hidden rounded-full bg-slate-100">
            <div
              class="h-full rounded-full transition-all duration-500"
              :class="
                deploySuccessRate === null
                  ? 'bg-slate-200'
                  : data.deployment_stats.failed > 0
                    ? 'bg-amber-500'
                    : 'bg-emerald-500'
              "
              :style="{ width: `${deploySuccessRate ?? 0}%` }"
            />
          </div>
          <div class="mt-1.5 flex justify-between text-[11px] text-slate-500 tabular-nums">
            <span>待签发证书: {{ data.cert_stats.pending }}</span>
            <span>失败目标: {{ data.deployment_stats.failed }}</span>
          </div>
        </div>
      </div>
    </div>

    <!-- Audit Event Stream -->
    <section class="rounded-xl border border-slate-200 bg-white shadow-sm">
      <div class="flex flex-wrap items-center justify-between gap-3 border-b border-slate-200 px-5 py-4">
        <div>
          <h2 class="text-base font-semibold text-slate-900">近期运维事件流</h2>
          <p class="text-xs text-slate-500">最近 30 条签发、部署、Caddy 变更与安全审计记录</p>
        </div>

        <div class="flex items-center gap-1 rounded-lg bg-slate-100 p-1 text-xs font-medium">
          <button
            v-for="lv in [
              { id: 'all', label: '全部' },
              { id: 'info', label: '信息' },
              { id: 'warn', label: '警告' },
              { id: 'error', label: '错误' },
            ] as const"
            :key="lv.id"
            type="button"
            class="inline-flex items-center gap-1 rounded-md px-2.5 py-1 transition"
            :class="
              levelFilter === lv.id
                ? 'bg-white text-slate-900 shadow-sm'
                : 'text-slate-600 hover:text-slate-900'
            "
            @click="levelFilter = lv.id"
          >
            <span>{{ lv.label }}</span>
            <span class="text-[11px] text-slate-400 tabular-nums">{{ levelCounts[lv.id] }}</span>
          </button>
        </div>
      </div>

      <div v-if="loading && !data" class="p-8 text-center text-sm text-slate-500">
        正在加载概览数据...
      </div>
      <div v-else-if="filteredEvents.length === 0" class="p-10 text-center text-sm text-slate-500">
        暂无匹配的审计事件记录
      </div>
      <div v-else class="divide-y divide-slate-100">
        <div
          v-for="ev in filteredEvents"
          :key="ev.id"
          class="flex flex-col gap-2 px-5 py-3.5 transition sm:flex-row sm:items-center sm:justify-between"
          :class="getAuditTargetRoute(ev) ? 'cursor-pointer hover:bg-indigo-50/40' : 'hover:bg-slate-50/80'"
          @click="handleAuditClick(ev)"
        >
          <div class="min-w-0 flex-1 space-y-1">
            <div class="flex flex-wrap items-center gap-2">
              <StatusBadge :status="ev.level" />
              <span
                class="rounded bg-slate-100 px-2 py-0.5 text-[11px] font-medium text-slate-700"
                :title="ev.event_type"
              >
                {{ formatEventType(ev) }}
              </span>
              <span v-if="ev.target_name" class="text-xs font-semibold text-slate-800">
                {{ ev.target_name }}
              </span>
              <ExternalLink
                v-if="getAuditTargetRoute(ev)"
                class="h-3 w-3 text-slate-400"
              />
            </div>
            <p class="text-sm text-slate-600 break-words">{{ ev.message }}</p>
          </div>

          <div class="shrink-0 text-left text-xs text-slate-400 sm:text-right">
            <div class="font-medium text-slate-500" :title="formatDateTime(ev.created_at)">
              {{ formatRelativeTime(ev.created_at) }}
            </div>
            <div class="mt-0.5 font-mono text-[11px] tabular-nums">
              {{ formatDateTime(ev.created_at) }}
              <span v-if="ev.actor_ip">· {{ ev.actor_ip }}</span>
            </div>
          </div>
        </div>
      </div>
    </section>
  </div>
</template>
