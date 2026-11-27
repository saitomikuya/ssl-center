<script setup lang="ts">
import { computed, onMounted, reactive, ref, watch } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import {
  CheckCircle2,
  Cloud,
  Copy,
  Download,
  Edit3,
  FlaskConical,
  KeyRound,
  Plus,
  RefreshCw,
  Search,
  Star,
  Trash2,
} from 'lucide-vue-next'
import {
  createCAAccount,
  deleteCAAccount,
  exportCAKey,
  listCAAccounts,
  setDefaultCAAccount,
  updateCAAccount,
} from '@/api/ca'
import {
  createDNSCredential,
  deleteDNSCredential,
  listDNSCredentials,
  matchDNSZones,
  testDNSCredential,
  updateDNSCredential,
} from '@/api/dns'
import { ApiError } from '@/api/client'
import ConfirmDialog from '@/components/ui/ConfirmDialog.vue'
import ModalDialog from '@/components/ui/ModalDialog.vue'
import StatusBadge from '@/components/ui/StatusBadge.vue'
import { showToast } from '@/stores/toast'
import { copyToClipboard, formatDateTime } from '@/utils/format'
import type {
  CAAccountDTO,
  CAEnvironment,
  CAProvider,
  DNSCredentialDTO,
  DNSProvider,
  DNSTestResponse,
  DNSZone,
  ExportCAKeyResponse,
} from '@/types/api'

const route = useRoute()
const router = useRouter()

const activeTab = ref<'ca' | 'dns'>(route.query.tab === 'dns' ? 'dns' : 'ca')

watch(
  () => route.query.tab,
  (tab) => {
    if (tab === 'dns' || tab === 'ca') activeTab.value = tab
  },
)

function switchTab(tab: 'ca' | 'dns') {
  activeTab.value = tab
  void router.replace({ query: { ...route.query, tab } })
}

// ============================================================================
// CA Accounts State & Actions
// ============================================================================
const caList = ref<CAAccountDTO[]>([])
const caLoading = ref(false)
const caModalOpen = ref(false)
const caEditing = ref<CAAccountDTO | null>(null)
const caSubmitting = ref(false)
const gtsMode = ref<'eab' | 'import'>('eab')

const caForm = reactive({
  name: '',
  provider: 'letsencrypt' as CAProvider,
  environment: 'production' as CAEnvironment,
  email: '',
  is_default: false,
  eab_kid: '',
  eab_mac_key: '',
  acme_key_pem: '',
  account_uri: '',
})

const exportKeyModalOpen = ref(false)
const exportKeyData = ref<ExportCAKeyResponse | null>(null)
const exportKeyLoading = ref(false)

async function loadCAs() {
  caLoading.value = true
  try {
    caList.value = await listCAAccounts()
  } catch (err) {
    showToast('error', err instanceof Error ? err.message : '加载 CA 账户失败')
  } finally {
    caLoading.value = false
  }
}

function openCreateCA() {
  caEditing.value = null
  gtsMode.value = 'eab'
  Object.assign(caForm, {
    name: '',
    provider: 'letsencrypt',
    environment: 'production',
    email: '',
    is_default: caList.value.length === 0,
    eab_kid: '',
    eab_mac_key: '',
    acme_key_pem: '',
    account_uri: '',
  })
  caModalOpen.value = true
}

function openEditCA(item: CAAccountDTO) {
  caEditing.value = item
  Object.assign(caForm, {
    name: item.name,
    provider: item.provider as CAProvider,
    environment: item.environment as CAEnvironment,
    email: item.email,
    is_default: item.is_default,
    eab_kid: '',
    eab_mac_key: '',
    acme_key_pem: '',
    account_uri: item.account_uri,
  })
  caModalOpen.value = true
}

async function submitCA() {
  if (!caForm.name.trim() || !caForm.email.trim()) {
    showToast('warning', '请填写账户名称和联系邮箱')
    return
  }

  caSubmitting.value = true
  try {
    if (caEditing.value) {
      await updateCAAccount(caEditing.value.id, {
        name: caForm.name.trim(),
        email: caForm.email.trim(),
        is_default: caForm.is_default,
      })
      showToast('success', 'CA 账户已更新')
    } else {
      if (caForm.provider === 'gts') {
        if (gtsMode.value === 'eab' && (!caForm.eab_kid.trim() || !caForm.eab_mac_key.trim())) {
          showToast('warning', 'GTS EAB 注册需要填写 EAB Key ID 和 HMAC Key')
          caSubmitting.value = false
          return
        }
        if (gtsMode.value === 'import' && !caForm.acme_key_pem.trim()) {
          showToast('warning', '请粘贴或导入已有 acme.key PEM 内容')
          caSubmitting.value = false
          return
        }
      }
      await createCAAccount({
        name: caForm.name.trim(),
        provider: caForm.provider,
        environment: caForm.environment,
        email: caForm.email.trim(),
        is_default: caForm.is_default,
        eab_kid: caForm.provider === 'gts' && gtsMode.value === 'eab' ? caForm.eab_kid.trim() : undefined,
        eab_mac_key:
          caForm.provider === 'gts' && gtsMode.value === 'eab' ? caForm.eab_mac_key.trim() : undefined,
        acme_key_pem:
          caForm.provider === 'gts' && gtsMode.value === 'import' ? caForm.acme_key_pem.trim() : undefined,
        account_uri:
          caForm.provider === 'gts' && gtsMode.value === 'import' && caForm.account_uri.trim()
            ? caForm.account_uri.trim()
            : undefined,
      })
      showToast('success', 'CA 账户创建成功')
    }
    caModalOpen.value = false
    await loadCAs()
  } catch (err) {
    showToast('error', err instanceof Error ? err.message : '保存 CA 账户失败')
  } finally {
    caSubmitting.value = false
  }
}

async function handleSetDefaultCA(item: CAAccountDTO) {
  try {
    await setDefaultCAAccount(item.id)
    showToast('success', `已将「${item.name}」设为默认 CA`)
    await loadCAs()
  } catch (err) {
    showToast('error', err instanceof Error ? err.message : '设置默认 CA 失败')
  }
}

async function handleExportCAKey(item: CAAccountDTO) {
  exportKeyLoading.value = true
  exportKeyData.value = null
  exportKeyModalOpen.value = true
  try {
    exportKeyData.value = await exportCAKey(item.id)
  } catch (err) {
    exportKeyModalOpen.value = false
    showToast('error', err instanceof Error ? err.message : '导出 acme.key 失败')
  } finally {
    exportKeyLoading.value = false
  }
}

async function copyExportKey() {
  if (!exportKeyData.value) return
  const ok = await copyToClipboard(exportKeyData.value.acme_key_pem)
  showToast(ok ? 'success' : 'error', ok ? '已复制 acme.key PEM' : '复制失败')
}

function downloadExportKey() {
  if (!exportKeyData.value) return
  const blob = new Blob([exportKeyData.value.acme_key_pem], { type: 'application/x-pem-file' })
  const url = URL.createObjectURL(blob)
  const a = document.createElement('a')
  a.href = url
  a.download = `acme-${exportKeyData.value.provider}-${exportKeyData.value.id}.key.pem`
  document.body.appendChild(a)
  a.click()
  document.body.removeChild(a)
  URL.revokeObjectURL(url)
}

function handlePemFileSelect(event: Event) {
  const input = event.target as HTMLInputElement
  const file = input.files?.[0]
  if (!file) return
  const reader = new FileReader()
  reader.onload = () => {
    if (typeof reader.result === 'string') {
      caForm.acme_key_pem = reader.result
    }
  }
  reader.readAsText(file)
}

// ============================================================================
// DNS Credentials State & Actions
// ============================================================================
const dnsList = ref<DNSCredentialDTO[]>([])
const dnsLoading = ref(false)
const dnsModalOpen = ref(false)
const dnsEditing = ref<DNSCredentialDTO | null>(null)
const dnsSubmitting = ref(false)

const dnsForm = reactive({
  name: '',
  provider: 'cloudflare' as DNSProvider,
  api_token: '',
  access_key: '',
  secret_key: '',
  region: 'cn-north-4',
})

// DNS Test & Zone Match Modal
const dnsTestModalOpen = ref(false)
const dnsTestingTarget = ref<DNSCredentialDTO | null>(null)
const dnsTestingLoading = ref(false)
const dnsTestResult = ref<DNSTestResponse | null>(null)
const dnsTestError = ref('')
const zoneMatchDomain = ref('*.example.com')
const zoneMatchLoading = ref(false)
const zoneMatchResult = ref<string | null>(null)
const visibleZones = computed<DNSZone[]>(() => dnsTestResult.value?.zones || [])

async function loadDNS() {
  dnsLoading.value = true
  try {
    dnsList.value = await listDNSCredentials()
  } catch (err) {
    showToast('error', err instanceof Error ? err.message : '加载 DNS 凭据失败')
  } finally {
    dnsLoading.value = false
  }
}

function openCreateDNS() {
  dnsEditing.value = null
  Object.assign(dnsForm, {
    name: '',
    provider: 'cloudflare',
    api_token: '',
    access_key: '',
    secret_key: '',
    region: 'cn-north-4',
  })
  dnsModalOpen.value = true
}

function openEditDNS(item: DNSCredentialDTO) {
  dnsEditing.value = item
  Object.assign(dnsForm, {
    name: item.name,
    provider: item.provider as DNSProvider,
    api_token: '',
    access_key: '',
    secret_key: '',
    region: item.region || 'cn-north-4',
  })
  dnsModalOpen.value = true
}

async function submitDNS() {
  if (!dnsForm.name.trim()) {
    showToast('warning', '请填写凭据名称')
    return
  }

  dnsSubmitting.value = true
  try {
    if (dnsEditing.value) {
      await updateDNSCredential(dnsEditing.value.id, {
        name: dnsForm.name.trim(),
        api_token:
          dnsForm.provider === 'cloudflare' && dnsForm.api_token.trim()
            ? dnsForm.api_token.trim()
            : undefined,
        access_key:
          dnsForm.provider === 'huaweicloud' && dnsForm.access_key.trim()
            ? dnsForm.access_key.trim()
            : undefined,
        secret_key:
          dnsForm.provider === 'huaweicloud' && dnsForm.secret_key.trim()
            ? dnsForm.secret_key.trim()
            : undefined,
        region: dnsForm.provider === 'huaweicloud' ? dnsForm.region.trim() : undefined,
      })
      showToast('success', 'DNS 凭据已更新')
    } else {
      if (dnsForm.provider === 'cloudflare' && !dnsForm.api_token.trim()) {
        showToast('warning', '请填写 Cloudflare API Token')
        dnsSubmitting.value = false
        return
      }
      if (
        dnsForm.provider === 'huaweicloud' &&
        (!dnsForm.access_key.trim() || !dnsForm.secret_key.trim() || !dnsForm.region.trim())
      ) {
        showToast('warning', '请填写华为云 AK、SK 与 Region')
        dnsSubmitting.value = false
        return
      }
      await createDNSCredential({
        name: dnsForm.name.trim(),
        provider: dnsForm.provider,
        api_token: dnsForm.provider === 'cloudflare' ? dnsForm.api_token.trim() : undefined,
        access_key: dnsForm.provider === 'huaweicloud' ? dnsForm.access_key.trim() : undefined,
        secret_key: dnsForm.provider === 'huaweicloud' ? dnsForm.secret_key.trim() : undefined,
        region: dnsForm.provider === 'huaweicloud' ? dnsForm.region.trim() : undefined,
      })
      showToast('success', 'DNS 凭据创建成功')
    }
    dnsModalOpen.value = false
    await loadDNS()
  } catch (err) {
    showToast('error', err instanceof Error ? err.message : '保存 DNS 凭据失败')
  } finally {
    dnsSubmitting.value = false
  }
}

async function handleTestDNS(item: DNSCredentialDTO) {
  dnsTestingTarget.value = item
  dnsTestResult.value = null
  dnsTestError.value = ''
  zoneMatchResult.value = null
  dnsTestModalOpen.value = true
  dnsTestingLoading.value = true
  try {
    dnsTestResult.value = await testDNSCredential(item.id)
    if (dnsTestResult.value.zones.length > 0) {
      zoneMatchDomain.value = `app.${dnsTestResult.value.zones[0].name}`
    }
    await loadDNS()
  } catch (err) {
    dnsTestError.value = err instanceof Error ? err.message : '凭据测试失败'
  } finally {
    dnsTestingLoading.value = false
  }
}

async function handleMatchZone() {
  if (!dnsTestingTarget.value || !zoneMatchDomain.value.trim()) return
  zoneMatchLoading.value = true
  zoneMatchResult.value = null
  try {
    const res = await matchDNSZones(dnsTestingTarget.value.id, zoneMatchDomain.value.trim())
    zoneMatchResult.value = res.matched_zone || '未匹配到可见 Zone'
    if (res.zones && res.zones.length > 0 && dnsTestResult.value) {
      dnsTestResult.value.zones = res.zones
    }
  } catch (err) {
    showToast('error', err instanceof Error ? err.message : 'Zone 匹配测试失败')
  } finally {
    zoneMatchLoading.value = false
  }
}

// ============================================================================
// Delete Confirmation
// ============================================================================
const confirmOpen = ref(false)
const confirmTitle = ref('')
const confirmMessage = ref('')
const confirmLoading = ref(false)
let pendingDeleteAction: (() => Promise<void>) | null = null

function requestDeleteCA(item: CAAccountDTO) {
  confirmTitle.value = '删除 CA 账户'
  confirmMessage.value = `确定要删除 CA 账户「${item.name}」吗？\n若已有证书引用该账户，删除将被阻止。`
  pendingDeleteAction = async () => {
    await deleteCAAccount(item.id)
    showToast('success', 'CA 账户已删除')
    await loadCAs()
  }
  confirmOpen.value = true
}

function requestDeleteDNS(item: DNSCredentialDTO) {
  confirmTitle.value = '删除 DNS 凭据'
  confirmMessage.value = `确定要删除 DNS 凭据「${item.name}」吗？\n若已有证书引用该凭据，删除将被阻止。`
  pendingDeleteAction = async () => {
    await deleteDNSCredential(item.id)
    showToast('success', 'DNS 凭据已删除')
    await loadDNS()
  }
  confirmOpen.value = true
}

async function runConfirmDelete() {
  if (!pendingDeleteAction) return
  confirmLoading.value = true
  try {
    await pendingDeleteAction()
    confirmOpen.value = false
  } catch (err) {
    if (err instanceof ApiError && err.code === 'RESOURCE_IN_USE') {
      showToast('error', '该凭据正被现有证书引用，请先调整或删除关联证书')
    } else {
      showToast('error', err instanceof Error ? err.message : '删除失败')
    }
  } finally {
    confirmLoading.value = false
  }
}

onMounted(() => {
  void loadCAs()
  void loadDNS()
})
</script>

<template>
  <div class="space-y-6">
    <!-- Header -->
    <div class="flex flex-wrap items-center justify-between gap-4">
      <div>
        <h1 class="text-2xl font-bold tracking-tight text-slate-900">凭据中心</h1>
        <p class="mt-1 text-sm text-slate-500">
          集中管理 ACME CA 账户（Let's Encrypt / GTS）与多账号 DNS 解析凭据
        </p>
      </div>
      <div class="flex items-center gap-2">
        <button
          v-if="activeTab === 'ca'"
          type="button"
          class="inline-flex items-center gap-2 rounded-lg bg-indigo-600 px-4 py-2 text-sm font-semibold text-white shadow-sm hover:bg-indigo-700"
          @click="openCreateCA"
        >
          <Plus class="h-4 w-4" />
          新建 CA 账户
        </button>
        <button
          v-else
          type="button"
          class="inline-flex items-center gap-2 rounded-lg bg-indigo-600 px-4 py-2 text-sm font-semibold text-white shadow-sm hover:bg-indigo-700"
          @click="openCreateDNS"
        >
          <Plus class="h-4 w-4" />
          新建 DNS 凭据
        </button>
      </div>
    </div>

    <!-- Tabs -->
    <div class="border-b border-slate-200">
      <div class="flex gap-6">
        <button
          type="button"
          class="flex items-center gap-2 border-b-2 pb-3 text-sm font-semibold transition"
          :class="
            activeTab === 'ca'
              ? 'border-indigo-600 text-indigo-600'
              : 'border-transparent text-slate-500 hover:text-slate-800'
          "
          @click="switchTab('ca')"
        >
          <KeyRound class="h-4 w-4" />
          CA 账户
          <span class="rounded-full bg-slate-100 px-2 py-0.5 text-xs text-slate-600 tabular-nums">
            {{ caList.length }}
          </span>
        </button>

        <button
          type="button"
          class="flex items-center gap-2 border-b-2 pb-3 text-sm font-semibold transition"
          :class="
            activeTab === 'dns'
              ? 'border-indigo-600 text-indigo-600'
              : 'border-transparent text-slate-500 hover:text-slate-800'
          "
          @click="switchTab('dns')"
        >
          <Cloud class="h-4 w-4" />
          DNS 凭据
          <span class="rounded-full bg-slate-100 px-2 py-0.5 text-xs text-slate-600 tabular-nums">
            {{ dnsList.length }}
          </span>
        </button>
      </div>
    </div>

    <!-- Tab 1: CA Accounts -->
    <div v-if="activeTab === 'ca'" class="space-y-4">
      <div v-if="caLoading && caList.length === 0" class="rounded-xl border border-slate-200 bg-white p-10 text-center text-sm text-slate-500">
        正在加载 CA 账户...
      </div>
      <div v-else-if="caList.length === 0" class="rounded-xl border border-dashed border-slate-300 bg-white p-12 text-center">
        <KeyRound class="mx-auto h-10 w-10 text-slate-300" />
        <h3 class="mt-3 text-sm font-semibold text-slate-900">尚未配置 CA 签发账户</h3>
        <p class="mt-1 text-xs text-slate-500">
          支持 Let's Encrypt（免 EAB 开箱即用）或 Google Trust Services（EAB / acme.key 导入）
        </p>
        <button
          type="button"
          class="mt-4 inline-flex items-center gap-1.5 rounded-lg bg-indigo-600 px-4 py-2 text-xs font-semibold text-white hover:bg-indigo-700"
          @click="openCreateCA"
        >
          <Plus class="h-4 w-4" />
          创建第一个 CA 账户
        </button>
      </div>

      <div v-else class="grid gap-4 md:grid-cols-2">
        <div
          v-for="ca in caList"
          :key="ca.id"
          class="flex flex-col justify-between rounded-xl border bg-white p-5 shadow-sm transition"
          :class="ca.is_default ? 'border-indigo-200 ring-1 ring-indigo-100' : 'border-slate-200'"
        >
          <div>
            <div class="flex items-start justify-between gap-3">
              <div>
                <div class="flex flex-wrap items-center gap-2">
                  <h3 class="text-base font-semibold text-slate-900">{{ ca.name }}</h3>
                  <span
                    v-if="ca.is_default"
                    class="inline-flex items-center gap-1 rounded-full bg-indigo-50 px-2 py-0.5 text-xs font-semibold text-indigo-700"
                  >
                    <Star class="h-3 w-3 fill-indigo-600 text-indigo-600" />
                    默认
                  </span>
                  <StatusBadge :status="ca.status" />
                </div>
                <div class="mt-1.5 flex flex-wrap items-center gap-2 text-xs">
                  <span class="rounded bg-slate-100 px-2 py-0.5 font-medium text-slate-700">
                    {{ ca.provider === 'letsencrypt' ? "Let's Encrypt" : 'Google Trust Services (GTS)' }}
                  </span>
                  <span
                    class="rounded px-2 py-0.5 font-medium"
                    :class="
                      ca.environment === 'production'
                        ? 'bg-emerald-50 text-emerald-700'
                        : 'bg-amber-50 text-amber-700'
                    "
                  >
                    {{ ca.environment === 'production' ? '生产环境' : 'Staging 测试环境' }}
                  </span>
                </div>
              </div>
            </div>

            <dl class="mt-4 space-y-1.5 text-xs text-slate-600">
              <div class="flex justify-between gap-2">
                <dt class="text-slate-400">联系邮箱</dt>
                <dd class="font-medium text-slate-800">{{ ca.email }}</dd>
              </div>
              <div class="flex justify-between gap-2">
                <dt class="shrink-0 text-slate-400">Account URI</dt>
                <dd class="truncate font-mono text-[11px] text-slate-600" :title="ca.account_uri">
                  {{ ca.account_uri || '—' }}
                </dd>
              </div>
              <div class="flex justify-between gap-2">
                <dt class="text-slate-400">创建时间</dt>
                <dd class="tabular-nums">{{ formatDateTime(ca.created_at) }}</dd>
              </div>
            </dl>
          </div>

          <div class="mt-4 flex flex-wrap items-center justify-end gap-2 border-t border-slate-100 pt-3">
            <button
              v-if="!ca.is_default"
              type="button"
              class="inline-flex items-center gap-1 rounded-lg border border-slate-200 px-2.5 py-1.5 text-xs font-medium text-slate-700 hover:bg-slate-50"
              @click="handleSetDefaultCA(ca)"
            >
              <Star class="h-3.5 w-3.5 text-amber-500" />
              设为默认
            </button>
            <button
              type="button"
              class="inline-flex items-center gap-1 rounded-lg border border-slate-200 px-2.5 py-1.5 text-xs font-medium text-slate-700 hover:bg-slate-50"
              @click="handleExportCAKey(ca)"
            >
              <Download class="h-3.5 w-3.5 text-slate-500" />
              导出 acme.key
            </button>
            <button
              type="button"
              class="inline-flex items-center gap-1 rounded-lg border border-slate-200 px-2.5 py-1.5 text-xs font-medium text-slate-700 hover:bg-slate-50"
              @click="openEditCA(ca)"
            >
              <Edit3 class="h-3.5 w-3.5 text-slate-500" />
              编辑
            </button>
            <button
              type="button"
              class="inline-flex items-center gap-1 rounded-lg border border-rose-200 px-2.5 py-1.5 text-xs font-medium text-rose-600 hover:bg-rose-50"
              @click="requestDeleteCA(ca)"
            >
              <Trash2 class="h-3.5 w-3.5" />
              删除
            </button>
          </div>
        </div>
      </div>
    </div>

    <!-- Tab 2: DNS Credentials -->
    <div v-else class="space-y-4">
      <div v-if="dnsLoading && dnsList.length === 0" class="rounded-xl border border-slate-200 bg-white p-10 text-center text-sm text-slate-500">
        正在加载 DNS 凭据...
      </div>
      <div v-else-if="dnsList.length === 0" class="rounded-xl border border-dashed border-slate-300 bg-white p-12 text-center">
        <Cloud class="mx-auto h-10 w-10 text-slate-300" />
        <h3 class="mt-3 text-sm font-semibold text-slate-900">尚未配置 DNS 解析凭据</h3>
        <p class="mt-1 text-xs text-slate-500">
          支持 Cloudflare 与华为云 DNS 多账号命名，添加证书时自动匹配对应 Zone
        </p>
        <button
          type="button"
          class="mt-4 inline-flex items-center gap-1.5 rounded-lg bg-indigo-600 px-4 py-2 text-xs font-semibold text-white hover:bg-indigo-700"
          @click="openCreateDNS"
        >
          <Plus class="h-4 w-4" />
          添加第一个 DNS 凭据
        </button>
      </div>

      <div v-else class="grid gap-4 md:grid-cols-2">
        <div
          v-for="dns in dnsList"
          :key="dns.id"
          class="flex flex-col justify-between rounded-xl border border-slate-200 bg-white p-5 shadow-sm"
        >
          <div>
            <div class="flex items-start justify-between gap-3">
              <div>
                <div class="flex items-center gap-2">
                  <h3 class="text-base font-semibold text-slate-900">{{ dns.name }}</h3>
                  <StatusBadge
                    v-if="dns.last_test_ok !== null && dns.last_test_ok !== undefined"
                    :status="dns.last_test_ok ? 'success' : 'error'"
                    :label="dns.last_test_ok ? '测试通过' : '测试失败'"
                  />
                </div>
                <div class="mt-1.5 flex flex-wrap items-center gap-2 text-xs">
                  <span
                    class="rounded px-2 py-0.5 font-medium"
                    :class="
                      dns.provider === 'cloudflare'
                        ? 'bg-orange-50 text-orange-700'
                        : 'bg-red-50 text-red-700'
                    "
                  >
                    {{ dns.provider === 'cloudflare' ? 'Cloudflare DNS' : '华为云 DNS' }}
                  </span>
                  <span v-if="dns.region" class="rounded bg-slate-100 px-2 py-0.5 font-mono text-slate-600">
                    {{ dns.region }}
                  </span>
                  <span v-if="dns.has_secret" class="rounded bg-emerald-50 px-2 py-0.5 text-emerald-700">
                    密钥已加密存储
                  </span>
                </div>
              </div>
            </div>

            <dl class="mt-4 space-y-1.5 text-xs text-slate-600">
              <div class="flex justify-between gap-2">
                <dt class="text-slate-400">上次测试</dt>
                <dd class="tabular-nums">{{ formatDateTime(dns.last_tested_at) }}</dd>
              </div>
              <div v-if="dns.last_test_msg" class="flex justify-between gap-2">
                <dt class="shrink-0 text-slate-400">测试回显</dt>
                <dd class="truncate text-right text-slate-700" :title="dns.last_test_msg">
                  {{ dns.last_test_msg }}
                </dd>
              </div>
            </dl>
          </div>

          <div class="mt-4 flex flex-wrap items-center justify-end gap-2 border-t border-slate-100 pt-3">
            <button
              type="button"
              class="inline-flex items-center gap-1 rounded-lg border border-indigo-200 bg-indigo-50/60 px-2.5 py-1.5 text-xs font-medium text-indigo-700 hover:bg-indigo-100/70"
              @click="handleTestDNS(dns)"
            >
              <FlaskConical class="h-3.5 w-3.5" />
              测试凭据 &amp; Zone
            </button>
            <button
              type="button"
              class="inline-flex items-center gap-1 rounded-lg border border-slate-200 px-2.5 py-1.5 text-xs font-medium text-slate-700 hover:bg-slate-50"
              @click="openEditDNS(dns)"
            >
              <Edit3 class="h-3.5 w-3.5 text-slate-500" />
              编辑
            </button>
            <button
              type="button"
              class="inline-flex items-center gap-1 rounded-lg border border-rose-200 px-2.5 py-1.5 text-xs font-medium text-rose-600 hover:bg-rose-50"
              @click="requestDeleteDNS(dns)"
            >
              <Trash2 class="h-3.5 w-3.5" />
              删除
            </button>
          </div>
        </div>
      </div>
    </div>

    <!-- Create / Edit CA Modal -->
    <ModalDialog
      :open="caModalOpen"
      :title="caEditing ? '编辑 CA 账户' : '新建 CA 账户'"
      subtitle="支持 Let's Encrypt 免 EAB 注册与 Google Trust Services EAB / acme.key 导入"
      max-width="lg"
      @close="caModalOpen = false"
    >
      <div class="space-y-4">
        <div class="grid gap-4 sm:grid-cols-2">
          <div>
            <label class="mb-1 block text-xs font-medium text-slate-700">账户名称 *</label>
            <input
              v-model="caForm.name"
              type="text"
              placeholder="例如：LE 主力生产账号"
              class="w-full rounded-lg border border-slate-300 px-3 py-2 text-sm focus:border-indigo-500 focus:outline-none"
            />
          </div>
          <div>
            <label class="mb-1 block text-xs font-medium text-slate-700">联系邮箱 *</label>
            <input
              v-model="caForm.email"
              type="email"
              placeholder="ops@example.com"
              class="w-full rounded-lg border border-slate-300 px-3 py-2 text-sm focus:border-indigo-500 focus:outline-none"
            />
          </div>
        </div>

        <div v-if="!caEditing" class="grid gap-4 sm:grid-cols-2">
          <div>
            <label class="mb-1 block text-xs font-medium text-slate-700">签发机构 (CA)</label>
            <select
              v-model="caForm.provider"
              class="w-full rounded-lg border border-slate-300 bg-white px-3 py-2 text-sm focus:border-indigo-500 focus:outline-none"
            >
              <option value="letsencrypt">Let's Encrypt (免 EAB)</option>
              <option value="gts">Google Trust Services (GTS)</option>
            </select>
          </div>
          <div>
            <label class="mb-1 block text-xs font-medium text-slate-700">环境</label>
            <select
              v-model="caForm.environment"
              class="w-full rounded-lg border border-slate-300 bg-white px-3 py-2 text-sm focus:border-indigo-500 focus:outline-none"
            >
              <option value="production">Production (正式证书)</option>
              <option value="staging">Staging (测试环境)</option>
            </select>
          </div>
        </div>

        <!-- GTS specific fields -->
        <div
          v-if="!caEditing && caForm.provider === 'gts'"
          class="space-y-3 rounded-xl border border-slate-200 bg-slate-50 p-4"
        >
          <div class="flex items-center gap-4 text-xs font-medium">
            <label class="flex cursor-pointer items-center gap-1.5">
              <input v-model="gtsMode" type="radio" value="eab" class="text-indigo-600" />
              EAB 首次注册
            </label>
            <label class="flex cursor-pointer items-center gap-1.5">
              <input v-model="gtsMode" type="radio" value="import" class="text-indigo-600" />
              导入已有 acme.key (PEM)
            </label>
          </div>

          <template v-if="gtsMode === 'eab'">
            <div class="flex flex-wrap items-center justify-between gap-2 text-xs text-slate-500">
              <span>一次性 EAB 凭据仅用于完成 ACME 账户注册，注册成功后立即从内存销毁，不会写入数据库。</span>
              <a
                href="https://github.com/saitomikuya/ssl-center/blob/main/docs/GTS_EAB_GUIDE.md"
                target="_blank"
                rel="noopener noreferrer"
                class="inline-flex shrink-0 items-center gap-1 font-medium text-indigo-600 hover:text-indigo-700 hover:underline"
              >
                如何获取 EAB 凭据 ↗
              </a>
            </div>
            <div>
              <div class="mb-1 flex items-center justify-between gap-2">
                <label class="block text-xs font-medium text-slate-700">EAB Key ID (eab_kid) *</label>
                <a
                  href="https://github.com/saitomikuya/ssl-center/blob/main/docs/GTS_EAB_GUIDE.md"
                  target="_blank"
                  rel="noopener noreferrer"
                  class="text-[11px] font-medium text-indigo-600 hover:text-indigo-700 hover:underline"
                >
                  查看获取教程 ↗
                </a>
              </div>
              <input
                v-model="caForm.eab_kid"
                type="text"
                placeholder="从 Google Cloud Shell 获取的 EAB Key ID"
                class="w-full rounded-lg border border-slate-300 bg-white px-3 py-2 font-mono text-xs focus:border-indigo-500 focus:outline-none"
              />
            </div>
            <div>
              <div class="mb-1 flex items-center justify-between gap-2">
                <label class="block text-xs font-medium text-slate-700">EAB HMAC Key (eab_mac_key) *</label>
                <a
                  href="https://github.com/saitomikuya/ssl-center/blob/main/docs/GTS_EAB_GUIDE.md"
                  target="_blank"
                  rel="noopener noreferrer"
                  class="text-[11px] font-medium text-indigo-600 hover:text-indigo-700 hover:underline"
                >
                  查看获取教程 ↗
                </a>
              </div>
              <input
                v-model="caForm.eab_mac_key"
                type="password"
                placeholder="Base64URL HMAC 密钥"
                class="w-full rounded-lg border border-slate-300 bg-white px-3 py-2 font-mono text-xs focus:border-indigo-500 focus:outline-none"
              />
            </div>
          </template>

          <template v-else>
            <div>
              <div class="mb-1 flex items-center justify-between">
                <label class="text-xs font-medium text-slate-700">acme.key PEM 内容 *</label>
                <label class="cursor-pointer text-xs font-medium text-indigo-600 hover:text-indigo-700">
                  从文件读取
                  <input type="file" accept=".pem,.key,.txt" class="hidden" @change="handlePemFileSelect" />
                </label>
              </div>
              <textarea
                v-model="caForm.acme_key_pem"
                rows="4"
                placeholder="-----BEGIN EC PRIVATE KEY-----"
                class="w-full rounded-lg border border-slate-300 bg-white px-3 py-2 font-mono text-xs focus:border-indigo-500 focus:outline-none"
              />
            </div>
            <div>
              <label class="mb-1 block text-xs font-medium text-slate-700">Account URI（可选，留空自动从 CA 查询）</label>
              <input
                v-model="caForm.account_uri"
                type="text"
                placeholder="https://dv.acme-v02.api.pki.goog/account/..."
                class="w-full rounded-lg border border-slate-300 bg-white px-3 py-2 font-mono text-xs focus:border-indigo-500 focus:outline-none"
              />
            </div>
          </template>
        </div>

        <label class="flex cursor-pointer items-center gap-2 text-sm text-slate-700">
          <input v-model="caForm.is_default" type="checkbox" class="rounded border-slate-300 text-indigo-600" />
          设为默认 CA 账户
        </label>
      </div>

      <template #footer>
        <button
          type="button"
          class="rounded-lg border border-slate-300 bg-white px-4 py-2 text-sm font-medium text-slate-700 hover:bg-slate-50"
          @click="caModalOpen = false"
        >
          取消
        </button>
        <button
          type="button"
          :disabled="caSubmitting"
          class="rounded-lg bg-indigo-600 px-4 py-2 text-sm font-semibold text-white hover:bg-indigo-700 disabled:opacity-50"
          @click="submitCA"
        >
          {{ caSubmitting ? '提交中...' : caEditing ? '保存修改' : '注册并保存' }}
        </button>
      </template>
    </ModalDialog>

    <!-- Export acme.key Modal -->
    <ModalDialog
      :open="exportKeyModalOpen"
      title="导出 ACME 账户密钥 (acme.key)"
      subtitle="请妥善保管导出的私钥，可用于在其他实例免 EAB 恢复同账户"
      max-width="xl"
      @close="exportKeyModalOpen = false"
    >
      <div v-if="exportKeyLoading" class="py-8 text-center text-sm text-slate-500">
        正在解密导出密钥...
      </div>
      <div v-else-if="exportKeyData" class="space-y-3">
        <div class="grid gap-2 rounded-lg bg-slate-50 p-3 text-xs">
          <div><span class="text-slate-400">账户名称：</span>{{ exportKeyData.name }}</div>
          <div class="truncate"><span class="text-slate-400">Account URI：</span><span class="font-mono">{{ exportKeyData.account_uri }}</span></div>
        </div>
        <textarea
          :value="exportKeyData.acme_key_pem"
          readonly
          rows="8"
          class="w-full rounded-lg border border-slate-200 bg-slate-950 p-3 font-mono text-xs text-emerald-300"
        />
      </div>
      <template #footer>
        <button
          type="button"
          class="inline-flex items-center gap-1.5 rounded-lg border border-slate-300 bg-white px-3.5 py-2 text-sm font-medium text-slate-700 hover:bg-slate-50"
          @click="copyExportKey"
        >
          <Copy class="h-4 w-4" />
          复制 PEM
        </button>
        <button
          type="button"
          class="inline-flex items-center gap-1.5 rounded-lg bg-indigo-600 px-3.5 py-2 text-sm font-semibold text-white hover:bg-indigo-700"
          @click="downloadExportKey"
        >
          <Download class="h-4 w-4" />
          下载 .pem 文件
        </button>
      </template>
    </ModalDialog>

    <!-- Create / Edit DNS Modal -->
    <ModalDialog
      :open="dnsModalOpen"
      :title="dnsEditing ? '编辑 DNS 凭据' : '新建 DNS 凭据'"
      subtitle="同服务商可添加多个命名账号，编辑时密钥留空表示保持原值不变"
      max-width="lg"
      @close="dnsModalOpen = false"
    >
      <div class="space-y-4">
        <div>
          <label class="mb-1 block text-xs font-medium text-slate-700">凭据名称 *</label>
          <input
            v-model="dnsForm.name"
            type="text"
            placeholder="例如：主力 Cloudflare / 备用华为云"
            class="w-full rounded-lg border border-slate-300 px-3 py-2 text-sm focus:border-indigo-500 focus:outline-none"
          />
        </div>

        <div v-if="!dnsEditing">
          <label class="mb-1 block text-xs font-medium text-slate-700">DNS 服务商</label>
          <select
            v-model="dnsForm.provider"
            class="w-full rounded-lg border border-slate-300 bg-white px-3 py-2 text-sm focus:border-indigo-500 focus:outline-none"
          >
            <option value="cloudflare">Cloudflare DNS</option>
            <option value="huaweicloud">华为云 DNS (Huawei Cloud)</option>
          </select>
        </div>

        <div v-if="dnsForm.provider === 'cloudflare'">
          <label class="mb-1 block text-xs font-medium text-slate-700">
            API Token {{ dnsEditing ? '（留空保持原 Token 不变）' : '*' }}
          </label>
          <input
            v-model="dnsForm.api_token"
            type="password"
            :placeholder="dnsEditing ? '已加密存储，留空则不修改' : '具备 Zone:Read 与 DNS:Edit 权限的 API Token'"
            class="w-full rounded-lg border border-slate-300 px-3 py-2 font-mono text-xs focus:border-indigo-500 focus:outline-none"
          />
        </div>

        <template v-else>
          <div>
            <label class="mb-1 block text-xs font-medium text-slate-700">
              Access Key (AK) {{ dnsEditing ? '（留空保持原值）' : '*' }}
            </label>
            <input
              v-model="dnsForm.access_key"
              type="text"
              :placeholder="dnsEditing ? '留空保持原 AK 不变' : '华为云 IAM Access Key'"
              class="w-full rounded-lg border border-slate-300 px-3 py-2 font-mono text-xs focus:border-indigo-500 focus:outline-none"
            />
          </div>
          <div>
            <label class="mb-1 block text-xs font-medium text-slate-700">
              Secret Key (SK) {{ dnsEditing ? '（留空保持原值）' : '*' }}
            </label>
            <input
              v-model="dnsForm.secret_key"
              type="password"
              :placeholder="dnsEditing ? '留空保持原 SK 不变' : '华为云 IAM Secret Key'"
              class="w-full rounded-lg border border-slate-300 px-3 py-2 font-mono text-xs focus:border-indigo-500 focus:outline-none"
            />
          </div>
          <div>
            <label class="mb-1 block text-xs font-medium text-slate-700">Region *</label>
            <input
              v-model="dnsForm.region"
              type="text"
              placeholder="例如：cn-north-4 / ap-southeast-1"
              class="w-full rounded-lg border border-slate-300 px-3 py-2 font-mono text-xs focus:border-indigo-500 focus:outline-none"
            />
          </div>
        </template>
      </div>

      <template #footer>
        <button
          type="button"
          class="rounded-lg border border-slate-300 bg-white px-4 py-2 text-sm font-medium text-slate-700 hover:bg-slate-50"
          @click="dnsModalOpen = false"
        >
          取消
        </button>
        <button
          type="button"
          :disabled="dnsSubmitting"
          class="rounded-lg bg-indigo-600 px-4 py-2 text-sm font-semibold text-white hover:bg-indigo-700 disabled:opacity-50"
          @click="submitDNS"
        >
          {{ dnsSubmitting ? '保存中...' : '保存凭据' }}
        </button>
      </template>
    </ModalDialog>

    <!-- DNS Test & Zone Match Modal -->
    <ModalDialog
      :open="dnsTestModalOpen"
      :title="`测试 DNS 凭据 — ${dnsTestingTarget?.name || ''}`"
      subtitle="验证 API 连通性、拉取可见 Zone 并测试最长后缀自动匹配"
      max-width="xl"
      @close="dnsTestModalOpen = false"
    >
      <div v-if="dnsTestingLoading" class="flex items-center justify-center gap-2 py-10 text-sm text-slate-500">
        <RefreshCw class="h-4 w-4 animate-spin text-indigo-600" />
        正在连接服务商接口拉取 Zone 列表...
      </div>

      <div v-else-if="dnsTestError" class="rounded-lg border border-rose-200 bg-rose-50 p-4 text-sm text-rose-700">
        {{ dnsTestError }}
      </div>

      <div v-else-if="dnsTestResult" class="space-y-5">
        <div
          class="flex items-center gap-2.5 rounded-lg border p-3.5 text-sm"
          :class="
            dnsTestResult.ok
              ? 'border-emerald-200 bg-emerald-50 text-emerald-800'
              : 'border-rose-200 bg-rose-50 text-rose-800'
          "
        >
          <CheckCircle2 v-if="dnsTestResult.ok" class="h-5 w-5 shrink-0 text-emerald-600" />
          <div>
            <div class="font-semibold">{{ dnsTestResult.ok ? '连通性校验通过' : '连通性校验失败' }}</div>
            <div class="text-xs">{{ dnsTestResult.message }}</div>
          </div>
        </div>

        <div>
          <h4 class="mb-2 text-xs font-semibold uppercase tracking-wider text-slate-500">
            可见域名 Zone 列表 ({{ visibleZones.length }})
          </h4>
          <div
            v-if="visibleZones.length === 0"
            class="rounded-lg border border-slate-200 bg-slate-50 p-4 text-center text-xs text-slate-500"
          >
            当前凭据未返回可见 Zone
          </div>
          <div v-else class="custom-scrollbar max-h-48 overflow-y-auto rounded-lg border border-slate-200 divide-y divide-slate-100">
            <div
              v-for="z in visibleZones"
              :key="z.id"
              class="flex items-center justify-between px-3.5 py-2 text-xs"
            >
              <span class="font-mono font-medium text-slate-800">{{ z.name }}</span>
              <span class="font-mono text-[11px] text-slate-400">{{ z.id }}</span>
            </div>
          </div>
        </div>

        <!-- Interactive Zone Match Tester -->
        <div class="rounded-xl border border-slate-200 bg-slate-50 p-4">
          <h4 class="text-xs font-semibold text-slate-800">交互式 Zone 自动匹配测试</h4>
          <p class="mt-0.5 text-xs text-slate-500">输入任意域名或泛域名验证最长后缀匹配结果</p>
          <div class="mt-2.5 flex gap-2">
            <input
              v-model="zoneMatchDomain"
              type="text"
              placeholder="*.api.example.com"
              class="flex-1 rounded-lg border border-slate-300 bg-white px-3 py-1.5 font-mono text-xs focus:border-indigo-500 focus:outline-none"
              @keyup.enter="handleMatchZone"
            />
            <button
              type="button"
              :disabled="zoneMatchLoading"
              class="inline-flex items-center gap-1.5 rounded-lg bg-slate-900 px-3.5 py-1.5 text-xs font-medium text-white hover:bg-slate-800 disabled:opacity-50"
              @click="handleMatchZone"
            >
              <Search class="h-3.5 w-3.5" />
              {{ zoneMatchLoading ? '匹配中...' : '测试匹配' }}
            </button>
          </div>
          <div v-if="zoneMatchResult !== null" class="mt-2.5 text-xs">
            匹配 Zone：
            <span class="rounded bg-indigo-100 px-2 py-0.5 font-mono font-semibold text-indigo-800">
              {{ zoneMatchResult }}
            </span>
          </div>
        </div>
      </div>

      <template #footer>
        <button
          type="button"
          class="rounded-lg border border-slate-300 bg-white px-4 py-2 text-sm font-medium text-slate-700 hover:bg-slate-50"
          @click="dnsTestModalOpen = false"
        >
          关闭
        </button>
      </template>
    </ModalDialog>

    <!-- Delete Confirmation -->
    <ConfirmDialog
      :open="confirmOpen"
      :title="confirmTitle"
      :message="confirmMessage"
      confirm-text="确认删除"
      danger
      :loading="confirmLoading"
      @confirm="runConfirmDelete"
      @cancel="confirmOpen = false"
    />
  </div>
</template>
