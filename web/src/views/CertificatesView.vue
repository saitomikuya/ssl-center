<script setup lang="ts">
import { computed, onMounted, onUnmounted, reactive, ref, watch } from 'vue'
import { useRoute } from 'vue-router'
import {
  AlertCircle,
  CheckCircle2,
  Circle,
  Copy,
  Download,
  Edit3,
  FileText,
  Key,
  Loader2,
  Play,
  Plus,
  RefreshCw,
  RotateCw,
  Search,
  Send,
  ShieldCheck,
  Terminal,
  Trash2,
} from 'lucide-vue-next'
import { listCAAccounts } from '@/api/ca'
import {
  createCertificate,
  deleteCertificate,
  downloadCertificateBundle,
  exportCertificatePEM,
  getCertificate,
  getCertJob,
  getCertJobStreamUrl,
  issueCertificate,
  listCertificateJobs,
  listCertificates,
  updateCertificate,
} from '@/api/certificates'
import {
  createCertificateDeployment,
  deleteDeployment,
  listCertificateDeployments,
  listDeploymentLogs,
  pushDeployment,
  updateDeployment,
} from '@/api/deployments'
import { listDNSCredentials, matchDNSZones } from '@/api/dns'
import { listHosts } from '@/api/hosts'
import ConfirmDialog from '@/components/ui/ConfirmDialog.vue'
import DrawerPanel from '@/components/ui/DrawerPanel.vue'
import ModalDialog from '@/components/ui/ModalDialog.vue'
import StatusBadge from '@/components/ui/StatusBadge.vue'
import { showToast } from '@/stores/toast'
import { certSubdirName, copyToClipboard, formatDateTime, formatShortDate, truncateFingerprint } from '@/utils/format'
import type {
  CAAccountDTO,
  CertificateDTO,
  CertJobDTO,
  CertJobSSEEvent,
  CertJobStage,
  DeploymentDTO,
  DeployLog,
  DeployTemplate,
  DNSCredentialDTO,
  HostDTO,
  KeyType,
  ReloadMode,
} from '@/types/api'

const DEFAULT_STAGES: CertJobStage[] = [
  { stage: 'create_order', label: '创建订单', status: 'pending' },
  { stage: 'write_dns_txt', label: '写入 DNS TXT', status: 'pending' },
  { stage: 'wait_propagation', label: '等待传播', status: 'pending' },
  { stage: 'ca_validate', label: 'CA 校验签发', status: 'pending' },
  { stage: 'save_cert', label: '证书落盘', status: 'pending' },
  { stage: 'trigger_deploy', label: '触发关联部署', status: 'pending' },
]

// ============================================================================
// Main List State
// ============================================================================
const route = useRoute()
const certs = ref<CertificateDTO[]>([])
const caList = ref<CAAccountDTO[]>([])
const dnsList = ref<DNSCredentialDTO[]>([])
const hosts = ref<HostDTO[]>([])
const loading = ref(false)
const searchQuery = ref('')
const statusFilter = ref<string>('all')

async function loadAll() {
  loading.value = true
  try {
    const [cList, cas, dnss, hostList] = await Promise.all([
      listCertificates(),
      listCAAccounts(),
      listDNSCredentials(),
      listHosts(),
    ])
    certs.value = cList
    caList.value = cas
    dnsList.value = dnss
    hosts.value = hostList
    if (selectedCert.value) {
      const updated = cList.find((c) => c.id === selectedCert.value?.id)
      if (updated) selectedCert.value = updated
    }
  } catch (err) {
    showToast('error', err instanceof Error ? err.message : '加载证书列表失败')
  } finally {
    loading.value = false
  }
}

const filteredCerts = computed(() => {
  const q = searchQuery.value.trim().toLowerCase()
  return certs.value.filter((c) => {
    if (statusFilter.value !== 'all') {
      if (statusFilter.value === 'issue') {
        if (c.status !== 'error' && c.status !== 'expired') return false
      } else if (c.status !== statusFilter.value) {
        return false
      }
    }
    if (!q) return true
    return (
      c.name.toLowerCase().includes(q) ||
      c.domain.toLowerCase().includes(q) ||
      (c.sans || []).some((s) => s.toLowerCase().includes(q))
    )
  })
})

function syncBadge(c: CertificateDTO) {
  if (c.deployment_total === 0) {
    return { text: '未绑定', cls: 'bg-slate-100 text-slate-500' }
  }
  if (c.deployment_failed > 0) {
    return {
      text: `${c.deployment_success}/${c.deployment_total} 成功，${c.deployment_failed} 失败`,
      cls: 'bg-rose-50 text-rose-700',
    }
  }
  if (c.deployment_success === c.deployment_total) {
    return {
      text: `${c.deployment_success}/${c.deployment_total} 已同步`,
      cls: 'bg-emerald-50 text-emerald-700',
    }
  }
  return {
    text: `${c.deployment_success}/${c.deployment_total} 待同步`,
    cls: 'bg-amber-50 text-amber-700',
  }
}

function daysProgressPercent(c: CertificateDTO): number {
  if (c.days_remaining === undefined || c.days_remaining === null) return 0
  return Math.max(0, Math.min(100, Math.round((c.days_remaining / 90) * 100)))
}

function daysProgressColor(c: CertificateDTO): string {
  if (c.days_remaining === undefined || c.days_remaining === null) return 'bg-slate-300'
  if (c.days_remaining <= 0) return 'bg-rose-500'
  if (c.days_remaining <= c.renew_before_days) return 'bg-amber-500'
  return 'bg-emerald-500'
}

// ============================================================================
// Create / Edit Certificate Modal
// ============================================================================
const certModalOpen = ref(false)
const editingCert = ref<CertificateDTO | null>(null)
const certSaving = ref(false)
const matchedZoneHint = ref('')
const zonePreviewLoading = ref(false)

const certForm = reactive({
  name: '',
  domain: '',
  sansText: '',
  ca_account_id: 0,
  dns_credential_id: 0,
  zone_override: '',
  key_type: 'EC256' as KeyType,
  renew_before_days: 30,
  auto_renew: true,
})

function openCreateCert() {
  editingCert.value = null
  const defaultCA = caList.value.find((c) => c.is_default) || caList.value[0]
  const defaultDNS = dnsList.value[0]
  Object.assign(certForm, {
    name: '',
    domain: '',
    sansText: '',
    ca_account_id: defaultCA?.id || 0,
    dns_credential_id: defaultDNS?.id || 0,
    zone_override: '',
    key_type: 'EC256',
    renew_before_days: 30,
    auto_renew: true,
  })
  matchedZoneHint.value = ''
  certModalOpen.value = true
}

function openEditCert(c: CertificateDTO) {
  editingCert.value = c
  Object.assign(certForm, {
    name: c.name,
    domain: c.domain,
    sansText: (c.sans || []).join('\n'),
    ca_account_id: c.ca_account_id,
    dns_credential_id: c.dns_credential_id,
    zone_override: c.zone_override || '',
    key_type: (c.key_type || 'EC256') as KeyType,
    renew_before_days: c.renew_before_days || 30,
    auto_renew: c.auto_renew,
  })
  matchedZoneHint.value = ''
  certModalOpen.value = true
}

async function previewMatchedZone() {
  const credId = certForm.dns_credential_id
  const domain = certForm.domain.trim()
  if (!credId || !domain || !domain.includes('.')) {
    matchedZoneHint.value = ''
    return
  }
  zonePreviewLoading.value = true
  try {
    const res = await matchDNSZones(credId, domain)
    matchedZoneHint.value = res.matched_zone || '未匹配到可见 Zone'
  } catch {
    matchedZoneHint.value = ''
  } finally {
    zonePreviewLoading.value = false
  }
}

watch([() => certForm.dns_credential_id, () => certForm.domain], () => {
  if (certModalOpen.value) {
    void previewMatchedZone()
  }
})

function parseSANs(text: string): string[] {
  return Array.from(
    new Set(
      text
        .split(/[\n,\s]+/)
        .map((s) => s.trim())
        .filter(Boolean),
    ),
  )
}

async function submitCert() {
  const domain = certForm.domain.trim()
  if (!domain) {
    showToast('warning', '请填写主域名')
    return
  }
  if (!certForm.ca_account_id || !certForm.dns_credential_id) {
    showToast('warning', '请选择 CA 账户与 DNS 凭据')
    return
  }

  const name = certForm.name.trim() || domain
  const sans = parseSANs(certForm.sansText)

  certSaving.value = true
  try {
    if (editingCert.value) {
      await updateCertificate(editingCert.value.id, {
        name,
        domain,
        sans,
        ca_account_id: certForm.ca_account_id,
        dns_credential_id: certForm.dns_credential_id,
        zone_override: certForm.zone_override.trim(),
        key_type: certForm.key_type,
        renew_before_days: Number(certForm.renew_before_days),
        auto_renew: certForm.auto_renew,
      })
      showToast('success', '证书配置已更新')
    } else {
      await createCertificate({
        name,
        domain,
        sans,
        ca_account_id: certForm.ca_account_id,
        dns_credential_id: certForm.dns_credential_id,
        zone_override: certForm.zone_override.trim(),
        key_type: certForm.key_type,
        renew_before_days: Number(certForm.renew_before_days),
        auto_renew: certForm.auto_renew,
      })
      showToast('success', '证书已创建')
    }
    certModalOpen.value = false
    await loadAll()
  } catch (err) {
    showToast('error', err instanceof Error ? err.message : '保存证书失败')
  } finally {
    certSaving.value = false
  }
}

// ============================================================================
// Certificate Detail Drawer (3 Tabs)
// ============================================================================
const drawerOpen = ref(false)
const drawerMode = ref<'detail' | 'deployments'>('detail')
const drawerTab = ref<'info' | 'jobs' | 'deployments'>('info')
const selectedCert = ref<CertificateDTO | null>(null)

async function openDrawer(c: CertificateDTO, tab: 'info' | 'jobs' | 'deployments' = 'info') {
  selectedCert.value = c
  drawerMode.value = tab === 'deployments' ? 'deployments' : 'detail'
  drawerTab.value = tab
  drawerOpen.value = true
  await Promise.all([refreshCertDetail(c.id), loadJobs(c.id), loadCertDeployments(c.id)])
}

async function refreshCertDetail(certId: number) {
  try {
    const fresh = await getCertificate(certId)
    selectedCert.value = fresh
    const idx = certs.value.findIndex((c) => c.id === certId)
    if (idx !== -1) certs.value[idx] = fresh
  } catch {
    // ignore
  }
}

function closeDrawer() {
  stopStreamAndPolling()
  drawerOpen.value = false
}

// --- Tab 1: PEM Copy & ZIP Export ---
const copyingPEM = ref(false)
const privkeyConfirmOpen = ref(false)

async function handleCopyFullchain() {
  if (!selectedCert.value) return
  copyingPEM.value = true
  try {
    const res = await exportCertificatePEM(selectedCert.value.id, { include_private_key: false })
    const ok = await copyToClipboard(res.fullchain_pem)
    showToast(ok ? 'success' : 'error', ok ? '已复制 Fullchain PEM' : '复制失败')
  } catch (err) {
    showToast('error', err instanceof Error ? err.message : '获取证书 PEM 失败')
  } finally {
    copyingPEM.value = false
  }
}

async function handleCopyPrivkey() {
  if (!selectedCert.value) return
  copyingPEM.value = true
  try {
    const res = await exportCertificatePEM(selectedCert.value.id, { include_private_key: true })
    if (!res.privkey_pem) {
      showToast('warning', '私钥不可用，请确认证书已签发')
      return
    }
    const ok = await copyToClipboard(res.privkey_pem)
    privkeyConfirmOpen.value = false
    showToast(ok ? 'success' : 'error', ok ? '已复制私钥 PEM，请妥善保管' : '复制失败')
  } catch (err) {
    showToast('error', err instanceof Error ? err.message : '获取私钥 PEM 失败')
  } finally {
    copyingPEM.value = false
  }
}

async function handleDownloadBundle() {
  if (!selectedCert.value) return
  try {
    await downloadCertificateBundle(selectedCert.value.id)
    showToast('success', '证书包 ZIP 下载已开始')
  } catch (err) {
    showToast('error', err instanceof Error ? err.message : '下载证书包失败')
  }
}

// --- Tab 2: Issuance Jobs + SSE + Polling Fallback ---
const jobs = ref<CertJobDTO[]>([])
const activeJob = ref<CertJobDTO | null>(null)
const liveStages = ref<CertJobStage[]>([])
const liveLogs = ref<string[]>([])
const streamMode = ref<'idle' | 'sse' | 'polling' | 'done'>('idle')
const issuingCertId = ref<number | null>(null)

let eventSource: EventSource | null = null
let pollTimer: number | null = null

function stopStreamAndPolling() {
  if (eventSource) {
    eventSource.close()
    eventSource = null
  }
  if (pollTimer !== null) {
    window.clearInterval(pollTimer)
    pollTimer = null
  }
}

async function loadJobs(certId: number, focusJobId?: number) {
  try {
    const list = await listCertificateJobs(certId)
    jobs.value = list
    if (list.length === 0) {
      activeJob.value = null
      liveStages.value = [...DEFAULT_STAGES]
      liveLogs.value = []
      streamMode.value = 'idle'
      stopStreamAndPolling()
      return
    }
    const target = focusJobId ? list.find((j) => j.id === focusJobId) || list[0] : list[0]
    selectJob(target)
  } catch (err) {
    showToast('error', err instanceof Error ? err.message : '加载签发任务失败')
  }
}

function selectJob(job: CertJobDTO) {
  stopStreamAndPolling()
  activeJob.value = job
  liveStages.value = job.stages && job.stages.length > 0 ? [...job.stages] : [...DEFAULT_STAGES]
  liveLogs.value = job.logs ? job.logs.split('\n').filter((l) => l.length > 0) : []

  if (job.status === 'pending' || job.status === 'running') {
    connectSSE(job.id)
  } else {
    streamMode.value = 'done'
  }
}

function applySSEEvent(
  ev: CertJobSSEEvent,
  replayState?: { prefix: string[]; idx: number },
) {
  if (!activeJob.value || activeJob.value.id !== ev.job_id) return
  activeJob.value.status = ev.status
  activeJob.value.current_stage = ev.current_stage
  if (ev.error_message) activeJob.value.error_message = ev.error_message
  if (ev.stages && ev.stages.length > 0) {
    liveStages.value = ev.stages
    activeJob.value.stages = ev.stages
  }
  if (ev.log_line) {
    if (replayState && replayState.idx < replayState.prefix.length) {
      if (ev.log_line === replayState.prefix[replayState.idx]) {
        replayState.idx++
      } else {
        replayState.idx = replayState.prefix.length
        liveLogs.value.push(ev.log_line)
      }
    } else {
      liveLogs.value.push(ev.log_line)
    }
  }
  if (ev.type === 'done' || ev.status === 'success' || ev.status === 'failed') {
    streamMode.value = 'done'
    stopStreamAndPolling()
    if (selectedCert.value) {
      void refreshCertDetail(selectedCert.value.id)
      void loadCertDeployments(selectedCert.value.id)
    }
  }
}

function connectSSE(jobId: number) {
  const initialLogs = [...liveLogs.value]
  stopStreamAndPolling()
  streamMode.value = 'sse'

  const replayState = { prefix: initialLogs, idx: 0 }
  const es = new EventSource(getCertJobStreamUrl(jobId), { withCredentials: true })
  eventSource = es

  const parseAndApply = (raw: string) => {
    try {
      const payload = JSON.parse(raw) as CertJobSSEEvent
      applySSEEvent(payload, replayState)
    } catch {
      // ignore malformed frame
    }
  }

  es.addEventListener('stage', (e) => parseAndApply((e as MessageEvent).data))
  es.addEventListener('log', (e) => parseAndApply((e as MessageEvent).data))
  es.addEventListener('done', (e) => parseAndApply((e as MessageEvent).data))
  es.onmessage = (e) => parseAndApply(e.data)

  es.onerror = () => {
    // Only fallback to polling if job is still active
    es.close()
    if (eventSource === es) eventSource = null
    if (
      activeJob.value &&
      activeJob.value.id === jobId &&
      activeJob.value.status !== 'success' &&
      activeJob.value.status !== 'failed'
    ) {
      startPollingFallback(jobId)
    }
  }
}

function startPollingFallback(jobId: number) {
  if (pollTimer !== null) return
  streamMode.value = 'polling'

  const pollOnce = async () => {
    try {
      const fresh = await getCertJob(jobId)
      if (!activeJob.value || activeJob.value.id !== jobId) {
        stopStreamAndPolling()
        return
      }
      activeJob.value = fresh
      liveStages.value = fresh.stages && fresh.stages.length > 0 ? fresh.stages : [...DEFAULT_STAGES]
      liveLogs.value = fresh.logs ? fresh.logs.split('\n').filter((l) => l.length > 0) : []
      if (fresh.status === 'success' || fresh.status === 'failed') {
        streamMode.value = 'done'
        stopStreamAndPolling()
        if (selectedCert.value) {
          await refreshCertDetail(selectedCert.value.id)
          await loadCertDeployments(selectedCert.value.id)
        }
      }
    } catch {
      // keep polling silently on transient network blip
    }
  }

  void pollOnce()
  pollTimer = window.setInterval(pollOnce, 2000)
}

async function handleIssueCert(c: CertificateDTO) {
  issuingCertId.value = c.id
  try {
    const res = await issueCertificate(c.id)
    showToast('info', `签发任务 #${res.job_id} 已触发`)
    selectedCert.value = c
    drawerTab.value = 'jobs'
    drawerOpen.value = true
    await Promise.all([loadAll(), loadJobs(c.id, res.job_id), loadCertDeployments(c.id)])
  } catch (err) {
    showToast('error', err instanceof Error ? err.message : '触发签发失败')
  } finally {
    issuingCertId.value = null
  }
}

// --- Tab 3: Deployments & Deploy Logs ---
const certDeployments = ref<DeploymentDTO[]>([])
const deploymentsLoading = ref(false)
const deployModalOpen = ref(false)
const editingDeploy = ref<DeploymentDTO | null>(null)
const deploySaving = ref(false)
const pushingDeployId = ref<number | null>(null)

const deployForm = reactive({
  host_id: 0,
  name: '',
  template: 'caddy_docker' as DeployTemplate,
  enabled: true,
  fullchain_path: '',
  privkey_path: '',
  issuer_path: '',
  cert_file_mode: '0644',
  key_file_mode: '0600',
  reload_mode: 'docker_exec' as ReloadMode,
  reload_command: '',
  reload_webhook_url: '',
  tls_verify_enabled: true,
  tls_verify_host: '',
  tls_verify_port: 443,
  tls_verify_sni: '',
})

async function loadCertDeployments(certId: number) {
  deploymentsLoading.value = true
  try {
    certDeployments.value = await listCertificateDeployments(certId)
  } catch (err) {
    showToast('error', err instanceof Error ? err.message : '加载部署目标失败')
  } finally {
    deploymentsLoading.value = false
  }
}

function applyDeploymentDefaultsForHost(hostId: number, template: DeployTemplate) {
  if (!selectedCert.value) return
  const host = hosts.value.find((h) => h.id === hostId)
  if (!host) return

  const baseCertDir = (host.caddy_host_cert_dir || '/opt/caddy/certs').replace(/\/+$/, '')
  const subDir = `${baseCertDir}/${certSubdirName(selectedCert.value.domain, selectedCert.value.id)}`
  deployForm.fullchain_path = `${subDir}/fullchain.pem`
  deployForm.privkey_path = `${subDir}/privkey.pem`
  deployForm.issuer_path = `${subDir}/issuer.pem`

  if (!deployForm.name) {
    deployForm.name = `${host.name} Caddy`
  }

  if (template === 'caddy_docker') {
    deployForm.reload_mode = 'docker_exec'
    const container = host.caddy_container || 'caddy'
    const caddyfile = host.caddy_container_caddyfile || '/etc/caddy/Caddyfile'
    deployForm.reload_command = `docker exec '${container}' caddy reload --config '${caddyfile}' --force`
  } else if (template === 'local_dir') {
    deployForm.reload_mode = 'none'
    deployForm.reload_command = ''
  } else {
    deployForm.reload_mode = 'custom_cmd'
    deployForm.reload_command = ''
  }

  if (!deployForm.tls_verify_host && host.host && !host.is_local) {
    deployForm.tls_verify_host = host.host
  }
  if (!deployForm.tls_verify_sni) {
    const d = selectedCert.value.domain
    deployForm.tls_verify_sni = d.startsWith('*.') ? d.slice(2) : d
  }
}

function openCreateDeployment() {
  if (!selectedCert.value) return
  editingDeploy.value = null
  const firstHost = hosts.value.find((h) => !h.is_local) || hosts.value[0]
  const defaultTemplate: DeployTemplate =
    firstHost?.is_local && !firstHost.caddy_enabled ? 'local_dir' : 'caddy_docker'
  Object.assign(deployForm, {
    host_id: firstHost?.id || 0,
    name: '',
    template: defaultTemplate,
    enabled: true,
    fullchain_path: '',
    privkey_path: '',
    issuer_path: '',
    cert_file_mode: '0644',
    key_file_mode: '0600',
    reload_mode: 'docker_exec',
    reload_command: '',
    reload_webhook_url: '',
    tls_verify_enabled: true,
    tls_verify_host: '',
    tls_verify_port: 443,
    tls_verify_sni: '',
  })
  if (firstHost) {
    applyDeploymentDefaultsForHost(firstHost.id, defaultTemplate)
  }
  deployModalOpen.value = true
}

function openEditDeployment(d: DeploymentDTO) {
  editingDeploy.value = d
  Object.assign(deployForm, {
    host_id: d.host_id,
    name: d.name,
    template: d.template as DeployTemplate,
    enabled: d.enabled,
    fullchain_path: d.fullchain_path,
    privkey_path: d.privkey_path,
    issuer_path: d.issuer_path,
    cert_file_mode: d.cert_file_mode || '0644',
    key_file_mode: d.key_file_mode || '0600',
    reload_mode: d.reload_mode as ReloadMode,
    reload_command: d.reload_command,
    reload_webhook_url: d.reload_webhook_url,
    tls_verify_enabled: d.tls_verify_enabled,
    tls_verify_host: d.tls_verify_host,
    tls_verify_port: d.tls_verify_port || 443,
    tls_verify_sni: d.tls_verify_sni,
  })
  deployModalOpen.value = true
}

function onHostOrTemplateChange() {
  if (!editingDeploy.value) {
    deployForm.name = ''
    applyDeploymentDefaultsForHost(deployForm.host_id, deployForm.template)
  }
}

async function submitDeployment() {
  if (!selectedCert.value) return
  if (!deployForm.host_id || !deployForm.name.trim()) {
    showToast('warning', '请选择主机并填写部署名称')
    return
  }
  if (!deployForm.fullchain_path.trim() || !deployForm.privkey_path.trim()) {
    showToast('warning', '请填写 fullchain 与 privkey 写入路径')
    return
  }

  deploySaving.value = true
  try {
    if (editingDeploy.value) {
      await updateDeployment(editingDeploy.value.id, {
        name: deployForm.name.trim(),
        template: deployForm.template,
        enabled: deployForm.enabled,
        fullchain_path: deployForm.fullchain_path.trim(),
        privkey_path: deployForm.privkey_path.trim(),
        issuer_path: deployForm.issuer_path.trim(),
        cert_file_mode: deployForm.cert_file_mode.trim(),
        key_file_mode: deployForm.key_file_mode.trim(),
        reload_mode: deployForm.reload_mode,
        reload_command: deployForm.reload_command.trim(),
        reload_webhook_url: deployForm.reload_webhook_url.trim(),
        tls_verify_enabled: deployForm.tls_verify_enabled,
        tls_verify_host: deployForm.tls_verify_host.trim(),
        tls_verify_port: Number(deployForm.tls_verify_port) || 443,
        tls_verify_sni: deployForm.tls_verify_sni.trim(),
      })
      showToast('success', '部署目标已更新')
    } else {
      await createCertificateDeployment(selectedCert.value.id, {
        host_id: deployForm.host_id,
        name: deployForm.name.trim(),
        template: deployForm.template,
        enabled: deployForm.enabled,
        fullchain_path: deployForm.fullchain_path.trim(),
        privkey_path: deployForm.privkey_path.trim(),
        issuer_path: deployForm.issuer_path.trim(),
        cert_file_mode: deployForm.cert_file_mode.trim(),
        key_file_mode: deployForm.key_file_mode.trim(),
        reload_mode: deployForm.reload_mode,
        reload_command: deployForm.reload_command.trim(),
        reload_webhook_url: deployForm.reload_webhook_url.trim(),
        tls_verify_enabled: deployForm.tls_verify_enabled,
        tls_verify_host: deployForm.tls_verify_host.trim(),
        tls_verify_port: Number(deployForm.tls_verify_port) || 443,
        tls_verify_sni: deployForm.tls_verify_sni.trim(),
      })
      showToast('success', '部署目标已添加')
    }
    deployModalOpen.value = false
    await Promise.all([loadCertDeployments(selectedCert.value.id), loadAll()])
  } catch (err) {
    showToast('error', err instanceof Error ? err.message : '保存部署目标失败')
  } finally {
    deploySaving.value = false
  }
}

async function handlePushDeployment(d: DeploymentDTO) {
  pushingDeployId.value = d.id
  try {
    const log = await pushDeployment(d.id)
    if (log.status === 'success') {
      if (d.tls_verify_enabled && !log.tls_verified && log.error_message) {
        showToast('warning', `「${d.name}」证书已写入，首次 TLS 指纹尚未生效；请更新 Caddyfile 后再次推送验证`)
      } else {
        showToast('success', `「${d.name}」推送并校验成功`)
      }
    } else {
      showToast('error', `「${d.name}」推送失败: ${log.error_message || '请查看部署日志'}`)
    }
    if (selectedCert.value) {
      await Promise.all([loadCertDeployments(selectedCert.value.id), loadAll()])
    }
  } catch (err) {
    showToast('error', err instanceof Error ? err.message : '推送失败')
  } finally {
    pushingDeployId.value = null
  }
}

// --- Deploy Logs Modal ---
const logsModalOpen = ref(false)
const logsTargetName = ref('')
const deployLogs = ref<DeployLog[]>([])
const deployLogsLoading = ref(false)

async function openDeployLogs(d: DeploymentDTO) {
  logsTargetName.value = d.name
  logsModalOpen.value = true
  deployLogsLoading.value = true
  try {
    deployLogs.value = await listDeploymentLogs(d.id)
  } catch (err) {
    showToast('error', err instanceof Error ? err.message : '加载部署日志失败')
  } finally {
    deployLogsLoading.value = false
  }
}

// ============================================================================
// Delete Confirmations (Cert & Deployment)
// ============================================================================
const confirmOpen = ref(false)
const confirmTitle = ref('')
const confirmMessage = ref('')
const confirmLoading = ref(false)
let pendingDeleteFn: (() => Promise<void>) | null = null

function requestDeleteCert(c: CertificateDTO) {
  confirmTitle.value = '删除证书'
  confirmMessage.value = `确定要删除证书「${c.domain}」吗？\n删除后将同步清理磁盘证书文件及关联的部署目标与任务日志。`
  pendingDeleteFn = async () => {
    await deleteCertificate(c.id)
    if (selectedCert.value?.id === c.id) {
      closeDrawer()
    }
    showToast('success', '证书已删除')
    await loadAll()
  }
  confirmOpen.value = true
}

function requestDeleteDeployment(d: DeploymentDTO) {
  confirmTitle.value = '删除部署目标'
  confirmMessage.value = `确定要移除部署目标「${d.name}」吗？`
  pendingDeleteFn = async () => {
    await deleteDeployment(d.id)
    showToast('success', '部署目标已删除')
    if (selectedCert.value) {
      await Promise.all([loadCertDeployments(selectedCert.value.id), loadAll()])
    }
  }
  confirmOpen.value = true
}

async function runConfirmDelete() {
  if (!pendingDeleteFn) return
  confirmLoading.value = true
  try {
    await pendingDeleteFn()
    confirmOpen.value = false
  } catch (err) {
    showToast('error', err instanceof Error ? err.message : '删除失败')
  } finally {
    confirmLoading.value = false
  }
}

onMounted(async () => {
  await loadAll()
  const qCertId = Number(route.query.certId)
  if (qCertId) {
    const target = certs.value.find((c) => c.id === qCertId)
    if (target) {
      const qTab = route.query.tab
      const tab = qTab === 'deployments' || qTab === 'jobs' ? qTab : 'info'
      void openDrawer(target, tab)
    }
  }
})

onUnmounted(() => {
  stopStreamAndPolling()
})
</script>

<template>
  <div class="space-y-6">
    <!-- Header -->
    <div class="flex flex-wrap items-center justify-between gap-4">
      <div>
        <h1 class="text-2xl font-bold tracking-tight text-slate-900">证书管理</h1>
        <p class="mt-1 text-sm text-slate-500">
          全生命周期管理 ACME 证书、实时签发追踪与多主机纯推送部署
        </p>
      </div>
      <div class="flex items-center gap-2.5">
        <button
          type="button"
          class="inline-flex items-center gap-1.5 rounded-lg border border-slate-200 bg-white px-3.5 py-2 text-sm font-medium text-slate-700 shadow-sm hover:bg-slate-50"
          @click="loadAll"
        >
          <RefreshCw class="h-4 w-4" :class="loading ? 'animate-spin text-indigo-600' : 'text-slate-400'" />
          刷新
        </button>
        <button
          type="button"
          class="inline-flex items-center gap-1.5 rounded-lg bg-indigo-600 px-4 py-2 text-sm font-semibold text-white shadow-sm hover:bg-indigo-700"
          @click="openCreateCert"
        >
          <Plus class="h-4 w-4" />
          新建证书
        </button>
      </div>
    </div>

    <!-- Filter & Search Bar -->
    <div class="flex flex-wrap items-center justify-between gap-3 rounded-xl border border-slate-200 bg-white p-3.5 shadow-sm">
      <div class="relative min-w-[240px] flex-1 sm:max-w-xs">
        <Search class="pointer-events-none absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-slate-400" />
        <input
          v-model="searchQuery"
          type="text"
          placeholder="搜索名称、主域名或 SAN..."
          class="w-full rounded-lg border border-slate-200 bg-slate-50 py-1.5 pl-9 pr-3 text-sm focus:border-indigo-500 focus:bg-white focus:outline-none"
        />
      </div>

      <div class="flex flex-wrap items-center gap-1 rounded-lg bg-slate-100 p-1 text-xs font-medium">
        <button
          v-for="f in [
            { id: 'all', label: '全部' },
            { id: 'valid', label: '有效' },
            { id: 'expiring', label: '临期' },
            { id: 'issue', label: '异常/过期' },
            { id: 'issuing', label: '签发中' },
            { id: 'pending', label: '待签发' },
          ]"
          :key="f.id"
          type="button"
          class="rounded-md px-2.5 py-1 transition"
          :class="
            statusFilter === f.id
              ? 'bg-white text-slate-900 shadow-sm'
              : 'text-slate-600 hover:text-slate-900'
          "
          @click="statusFilter = f.id"
        >
          {{ f.label }}
        </button>
      </div>
    </div>

    <!-- Certificate Table -->
    <div class="overflow-hidden rounded-xl border border-slate-200 bg-white shadow-sm">
      <div v-if="loading && certs.length === 0" class="p-12 text-center text-sm text-slate-500">
        正在加载证书列表...
      </div>
      <div v-else-if="filteredCerts.length === 0" class="p-12 text-center">
        <ShieldCheck class="mx-auto h-10 w-10 text-slate-300" />
        <h3 class="mt-3 text-sm font-semibold text-slate-900">暂无匹配的证书</h3>
        <p class="mt-1 text-xs text-slate-500">点击「新建证书」配置域名并触发 DNS-01 自动签发</p>
      </div>
      <div v-else class="overflow-x-auto">
        <table class="min-w-full divide-y divide-slate-200 text-left text-sm">
          <thead class="bg-slate-50 text-xs font-semibold uppercase tracking-wider text-slate-500">
            <tr>
              <th class="px-5 py-3.5">域名 / SAN</th>
              <th class="px-4 py-3.5">CA &amp; DNS</th>
              <th class="px-4 py-3.5">状态 &amp; 剩余有效期</th>
              <th class="px-4 py-3.5">部署同步比</th>
              <th class="px-5 py-3.5 text-right">操作</th>
            </tr>
          </thead>
          <tbody class="divide-y divide-slate-100">
            <tr
              v-for="c in filteredCerts"
              :key="c.id"
              class="cursor-pointer transition hover:bg-slate-50/80"
              @click="openDrawer(c, 'info')"
            >
              <td class="px-5 py-4">
                <div class="font-semibold text-slate-900">{{ c.domain }}</div>
                <div class="mt-0.5 flex flex-wrap items-center gap-1.5 text-xs text-slate-500">
                  <span>{{ c.name }}</span>
                  <span class="rounded bg-slate-100 px-1.5 py-0.5 font-mono text-[10px] text-slate-600">
                    {{ c.key_type }}
                  </span>
                  <span v-if="c.sans && c.sans.length > 0" class="text-slate-400">
                    +{{ c.sans.length }} SAN
                  </span>
                </div>
              </td>

              <td class="px-4 py-4 text-xs text-slate-600">
                <div class="font-medium text-slate-800">{{ c.ca_account_name || `CA #${c.ca_account_id}` }}</div>
                <div class="mt-0.5 text-slate-500">{{ c.dns_credential_name || `DNS #${c.dns_credential_id}` }}</div>
              </td>

              <td class="px-4 py-4">
                <div class="flex items-center gap-2">
                  <StatusBadge :status="c.status" />
                  <span
                    v-if="c.days_remaining !== null && c.days_remaining !== undefined"
                    class="text-xs font-semibold text-slate-700 tabular-nums"
                  >
                    {{ c.days_remaining }} 天
                  </span>
                </div>
                <div class="mt-1.5 h-1.5 w-32 overflow-hidden rounded-full bg-slate-100">
                  <div
                    class="h-full rounded-full transition-all"
                    :class="daysProgressColor(c)"
                    :style="{ width: `${daysProgressPercent(c)}%` }"
                  />
                </div>
              </td>

              <td class="px-4 py-4">
                <button
                  type="button"
                  title="打开部署配置"
                  class="inline-flex items-center rounded-full px-2.5 py-0.5 text-xs font-medium tabular-nums transition hover:ring-1 hover:ring-indigo-300"
                  :class="syncBadge(c).cls"
                  @click.stop="openDrawer(c, 'deployments')"
                >
                  {{ syncBadge(c).text }}
                </button>
              </td>

              <td class="px-5 py-4 text-right" @click.stop>
                <div class="inline-flex items-center gap-1.5">
                  <button
                    type="button"
                    :disabled="issuingCertId === c.id"
                    class="inline-flex items-center gap-1 rounded-lg border border-indigo-200 bg-indigo-50 px-2.5 py-1.5 text-xs font-medium text-indigo-700 hover:bg-indigo-100 disabled:opacity-50"
                    @click="handleIssueCert(c)"
                  >
                    <Play class="h-3 w-3" />
                    {{ c.status === 'pending' ? '签发' : '续期' }}
                  </button>
                  <button
                    type="button"
                    class="inline-flex items-center gap-1 rounded-lg border border-slate-200 px-2.5 py-1.5 text-xs font-medium text-slate-700 hover:bg-slate-50"
                    @click="openDrawer(c, 'deployments')"
                  >
                    <Send class="h-3 w-3 text-slate-500" />
                    部署配置
                  </button>
                  <button
                    type="button"
                    class="rounded-lg border border-slate-200 px-2.5 py-1.5 text-xs font-medium text-slate-700 hover:bg-slate-50"
                    @click="openDrawer(c, 'info')"
                  >
                    详情
                  </button>
                  <button
                    type="button"
                    class="rounded-lg border border-slate-200 p-1.5 text-slate-500 hover:bg-slate-50 hover:text-slate-700"
                    title="编辑配置"
                    @click="openEditCert(c)"
                  >
                    <Edit3 class="h-3.5 w-3.5" />
                  </button>
                  <button
                    type="button"
                    class="rounded-lg border border-rose-200 p-1.5 text-rose-500 hover:bg-rose-50"
                    title="删除证书"
                    @click="requestDeleteCert(c)"
                  >
                    <Trash2 class="h-3.5 w-3.5" />
                  </button>
                </div>
              </td>
            </tr>
          </tbody>
        </table>
      </div>
    </div>

    <!-- Create / Edit Certificate Modal -->
    <ModalDialog
      :open="certModalOpen"
      :title="editingCert ? '编辑证书配置' : '新建证书'"
      subtitle="修改主域名后将自动清理旧证书文件并重置签发状态"
      max-width="xl"
      @close="certModalOpen = false"
    >
      <div class="space-y-4">
        <div class="grid gap-4 sm:grid-cols-2">
          <div>
            <label class="mb-1 block text-xs font-medium text-slate-700">主域名 (Primary Domain) *</label>
            <input
              v-model="certForm.domain"
              type="text"
              placeholder="example.com"
              class="w-full rounded-lg border border-slate-300 px-3 py-2 font-mono text-sm focus:border-indigo-500 focus:outline-none"
            />
          </div>
          <div>
            <label class="mb-1 block text-xs font-medium text-slate-700">备注名称</label>
            <input
              v-model="certForm.name"
              type="text"
              placeholder="默认与主域名相同"
              class="w-full rounded-lg border border-slate-300 px-3 py-2 text-sm focus:border-indigo-500 focus:outline-none"
            />
          </div>
        </div>

        <div>
          <label class="mb-1 block text-xs font-medium text-slate-700">
            附加 SAN 列表（可选，逗号或换行分隔，例如泛域名 *.example.com）
          </label>
          <textarea
            v-model="certForm.sansText"
            rows="2"
            placeholder="*.example.com"
            class="w-full rounded-lg border border-slate-300 px-3 py-2 font-mono text-xs focus:border-indigo-500 focus:outline-none"
          />
        </div>

        <div class="grid gap-4 sm:grid-cols-2">
          <div>
            <label class="mb-1 block text-xs font-medium text-slate-700">CA 签发账户 *</label>
            <select
              v-model.number="certForm.ca_account_id"
              class="w-full rounded-lg border border-slate-300 bg-white px-3 py-2 text-sm focus:border-indigo-500 focus:outline-none"
            >
              <option :value="0" disabled>请选择 CA 账户</option>
              <option v-for="ca in caList" :key="ca.id" :value="ca.id">
                {{ ca.name }} ({{ ca.provider }} / {{ ca.environment }})
              </option>
            </select>
          </div>
          <div>
            <label class="mb-1 block text-xs font-medium text-slate-700">DNS 解析凭据 *</label>
            <select
              v-model.number="certForm.dns_credential_id"
              class="w-full rounded-lg border border-slate-300 bg-white px-3 py-2 text-sm focus:border-indigo-500 focus:outline-none"
            >
              <option :value="0" disabled>请选择 DNS 凭据</option>
              <option v-for="dns in dnsList" :key="dns.id" :value="dns.id">
                {{ dns.name }} ({{ dns.provider }})
              </option>
            </select>
            <div v-if="zonePreviewLoading || matchedZoneHint" class="mt-1 text-[11px] text-slate-500">
              <span v-if="zonePreviewLoading">正在自动识别 Zone...</span>
              <span v-else>
                自动匹配 Zone:
                <span class="font-mono font-semibold text-indigo-600">{{ matchedZoneHint }}</span>
              </span>
            </div>
          </div>
        </div>

        <div class="grid gap-4 sm:grid-cols-3">
          <div>
            <label class="mb-1 block text-xs font-medium text-slate-700">密钥算法</label>
            <select
              v-model="certForm.key_type"
              class="w-full rounded-lg border border-slate-300 bg-white px-3 py-2 text-sm focus:border-indigo-500 focus:outline-none"
            >
              <option value="EC256">EC256 (推荐)</option>
              <option value="EC384">EC384</option>
              <option value="RSA2048">RSA2048</option>
            </select>
          </div>
          <div>
            <label class="mb-1 block text-xs font-medium text-slate-700">提前续期天数</label>
            <input
              v-model.number="certForm.renew_before_days"
              type="number"
              min="1"
              max="89"
              class="w-full rounded-lg border border-slate-300 px-3 py-2 text-sm tabular-nums focus:border-indigo-500 focus:outline-none"
            />
          </div>
          <div>
            <label class="mb-1 block text-xs font-medium text-slate-700">Zone 手动覆写（可选）</label>
            <input
              v-model="certForm.zone_override"
              type="text"
              placeholder="留空自动识别"
              class="w-full rounded-lg border border-slate-300 px-3 py-2 font-mono text-xs focus:border-indigo-500 focus:outline-none"
            />
          </div>
        </div>

        <label class="flex cursor-pointer items-center gap-2 text-sm text-slate-700">
          <input v-model="certForm.auto_renew" type="checkbox" class="rounded border-slate-300 text-indigo-600" />
          开启每日定时自动续期（剩余有效期 ≤ {{ certForm.renew_before_days }} 天触发）
        </label>
      </div>

      <template #footer>
        <button
          type="button"
          class="rounded-lg border border-slate-300 bg-white px-4 py-2 text-sm font-medium text-slate-700 hover:bg-slate-50"
          @click="certModalOpen = false"
        >
          取消
        </button>
        <button
          type="button"
          :disabled="certSaving"
          class="rounded-lg bg-indigo-600 px-4 py-2 text-sm font-semibold text-white hover:bg-indigo-700 disabled:opacity-50"
          @click="submitCert"
        >
          {{ certSaving ? '保存中...' : '保存证书' }}
        </button>
      </template>
    </ModalDialog>

    <!-- Certificate Detail / Deployment Config Drawer -->
    <DrawerPanel
      :open="drawerOpen"
      :title="drawerMode === 'deployments' ? `部署配置 — ${selectedCert?.domain || ''}` : selectedCert?.domain || '证书详情'"
      :subtitle="selectedCert ? (drawerMode === 'deployments' ? `${selectedCert.name} · 共 ${certDeployments.length} 个部署目标` : `${selectedCert.name} · ${selectedCert.key_type}`) : ''"
      width-class="max-w-3xl"
      @close="closeDrawer"
    >
      <template #headerExtra>
        <div v-if="drawerMode === 'detail'" class="flex gap-6 pt-2">
          <button
            type="button"
            class="border-b-2 pb-2.5 text-xs font-semibold transition"
            :class="
              drawerTab === 'info'
                ? 'border-indigo-600 text-indigo-600'
                : 'border-transparent text-slate-500 hover:text-slate-800'
            "
            @click="drawerTab = 'info'"
          >
            基本信息与导出
          </button>
          <button
            type="button"
            class="border-b-2 pb-2.5 text-xs font-semibold transition"
            :class="
              drawerTab === 'jobs'
                ? 'border-indigo-600 text-indigo-600'
                : 'border-transparent text-slate-500 hover:text-slate-800'
            "
            @click="drawerTab = 'jobs'"
          >
            签发进度与日志
          </button>
        </div>
      </template>

      <div v-if="selectedCert">
        <!-- Tab 1: Basic Info & Export -->
        <div v-if="drawerTab === 'info'" class="space-y-6">
          <div class="rounded-xl border border-slate-200 bg-slate-50 p-4">
            <div class="flex flex-wrap items-center justify-between gap-2">
              <div class="flex items-center gap-2">
                <StatusBadge :status="selectedCert.status" />
                <span class="text-sm font-semibold text-slate-900 tabular-nums">
                  {{
                    selectedCert.days_remaining !== null && selectedCert.days_remaining !== undefined
                      ? `剩余 ${selectedCert.days_remaining} 天`
                      : '尚未签发'
                  }}
                </span>
              </div>
              <span class="text-xs text-slate-500 tabular-nums">
                续期阈值: 到期前 {{ selectedCert.renew_before_days }} 天 ·
                {{ selectedCert.auto_renew ? '自动续期已开启' : '仅手动续期' }}
              </span>
            </div>
            <div class="mt-3 h-2 w-full overflow-hidden rounded-full bg-slate-200">
              <div
                class="h-full rounded-full transition-all"
                :class="daysProgressColor(selectedCert)"
                :style="{ width: `${daysProgressPercent(selectedCert)}%` }"
              />
            </div>
          </div>

          <div
            v-if="selectedCert.last_error"
            class="rounded-xl border border-rose-200 bg-rose-50 p-3.5 text-xs text-rose-700"
          >
            <div class="font-semibold">最近一次签发错误</div>
            <div class="mt-1 break-words">{{ selectedCert.last_error }}</div>
            <div v-if="selectedCert.next_retry_at" class="mt-1 font-mono text-[11px]">
              下次退避重试: {{ formatDateTime(selectedCert.next_retry_at) }} (已重试 {{ selectedCert.retry_count }} 次)
            </div>
          </div>

          <dl class="grid gap-3 rounded-xl border border-slate-200 bg-white p-4 text-xs sm:grid-cols-2">
            <div>
              <dt class="text-slate-400">颁发机构 (Issuer)</dt>
              <dd class="mt-1 font-medium text-slate-800">{{ selectedCert.issuer_name || '—' }}</dd>
            </div>
            <div>
              <dt class="text-slate-400">密钥算法</dt>
              <dd class="mt-1 font-mono font-medium text-slate-800">{{ selectedCert.key_type }}</dd>
            </div>
            <div>
              <dt class="text-slate-400">生效时间 (Not Before)</dt>
              <dd class="mt-1 font-mono tabular-nums text-slate-700">{{ formatDateTime(selectedCert.not_before) }}</dd>
            </div>
            <div>
              <dt class="text-slate-400">过期时间 (Not After)</dt>
              <dd class="mt-1 font-mono tabular-nums text-slate-700">{{ formatDateTime(selectedCert.not_after) }}</dd>
            </div>
            <div class="sm:col-span-2">
              <dt class="text-slate-400">实际签出 SAN 列表</dt>
              <dd class="mt-1.5 flex flex-wrap gap-1.5">
                <span
                  v-for="san in selectedCert.issued_sans && selectedCert.issued_sans.length > 0 ? selectedCert.issued_sans : selectedCert.sans"
                  :key="san"
                  class="rounded bg-slate-100 px-2 py-0.5 font-mono text-[11px] text-slate-700"
                >
                  {{ san }}
                </span>
                <span
                  v-if="(!selectedCert.issued_sans || selectedCert.issued_sans.length === 0) && (!selectedCert.sans || selectedCert.sans.length === 0)"
                  class="text-slate-400"
                >
                  {{ selectedCert.domain }}
                </span>
              </dd>
            </div>
            <div class="sm:col-span-2">
              <dt class="text-slate-400">叶证书 SHA-256 指纹</dt>
              <dd class="mt-1 flex items-center gap-2 font-mono text-[11px] text-slate-700 break-all">
                <span>{{ selectedCert.fingerprint_sha256 || '—' }}</span>
                <button
                  v-if="selectedCert.fingerprint_sha256"
                  type="button"
                  class="shrink-0 rounded p-1 text-slate-400 hover:bg-slate-100 hover:text-slate-700"
                  @click="copyToClipboard(selectedCert.fingerprint_sha256).then((ok) => showToast(ok ? 'success' : 'error', ok ? '已复制指纹' : '复制失败'))"
                >
                  <Copy class="h-3.5 w-3.5" />
                </button>
              </dd>
            </div>
          </dl>

          <!-- Export Actions -->
          <div class="rounded-xl border border-slate-200 bg-white p-4">
            <h4 class="mb-3 text-xs font-semibold uppercase tracking-wider text-slate-500">证书导出与快捷复制</h4>
            <div class="flex flex-wrap gap-2.5">
              <button
                type="button"
                :disabled="copyingPEM || !selectedCert.fingerprint_sha256"
                class="inline-flex items-center gap-1.5 rounded-lg border border-slate-300 bg-white px-3.5 py-2 text-xs font-medium text-slate-700 hover:bg-slate-50 disabled:opacity-50"
                @click="handleCopyFullchain"
              >
                <Copy class="h-3.5 w-3.5 text-slate-500" />
                复制 Fullchain PEM
              </button>
              <button
                type="button"
                :disabled="copyingPEM || !selectedCert.fingerprint_sha256"
                class="inline-flex items-center gap-1.5 rounded-lg border border-amber-300 bg-amber-50 px-3.5 py-2 text-xs font-medium text-amber-800 hover:bg-amber-100 disabled:opacity-50"
                @click="privkeyConfirmOpen = true"
              >
                <Key class="h-3.5 w-3.5" />
                复制私钥 PEM
              </button>
              <button
                type="button"
                :disabled="!selectedCert.fingerprint_sha256"
                class="inline-flex items-center gap-1.5 rounded-lg bg-indigo-600 px-3.5 py-2 text-xs font-semibold text-white hover:bg-indigo-700 disabled:opacity-50"
                @click="handleDownloadBundle"
              >
                <Download class="h-3.5 w-3.5" />
                下载证书包 (ZIP)
              </button>
            </div>
          </div>
        </div>

        <!-- Tab 2: Issuance Progress & Live Logs -->
        <div v-else-if="drawerTab === 'jobs'" class="space-y-5">
          <div class="flex flex-wrap items-center justify-between gap-3">
            <div class="flex items-center gap-2">
              <select
                v-if="jobs.length > 0"
                :value="activeJob?.id"
                class="rounded-lg border border-slate-300 bg-white px-3 py-1.5 text-xs font-medium text-slate-700"
                @change="(e) => {
                  const id = Number((e.target as HTMLSelectElement).value)
                  const found = jobs.find((j) => j.id === id)
                  if (found) selectJob(found)
                }"
              >
                <option v-for="j in jobs" :key="j.id" :value="j.id">
                  任务 #{{ j.id }} · {{ j.trigger_type }} · {{ formatShortDate(j.started_at) }} ({{ j.status }})
                </option>
              </select>
              <span
                class="rounded-full px-2.5 py-0.5 text-[11px] font-medium"
                :class="{
                  'bg-emerald-50 text-emerald-700': streamMode === 'sse',
                  'bg-amber-50 text-amber-700': streamMode === 'polling',
                  'bg-slate-100 text-slate-600': streamMode === 'done' || streamMode === 'idle',
                }"
              >
                {{
                  streamMode === 'sse'
                    ? 'SSE 实时推送'
                    : streamMode === 'polling'
                      ? '轮询降级同步中'
                      : streamMode === 'done'
                        ? '任务已结束'
                        : '暂无任务'
                }}
              </span>
            </div>

            <button
              type="button"
              :disabled="issuingCertId === selectedCert.id"
              class="inline-flex items-center gap-1.5 rounded-lg bg-indigo-600 px-3.5 py-1.5 text-xs font-semibold text-white hover:bg-indigo-700 disabled:opacity-50"
              @click="handleIssueCert(selectedCert)"
            >
              <Play class="h-3.5 w-3.5" />
              立即签发 / 强制续期
            </button>
          </div>

          <!-- 6-Stage Stepper -->
          <div class="grid gap-2 sm:grid-cols-2 lg:grid-cols-3">
            <div
              v-for="(st, idx) in liveStages"
              :key="st.stage"
              class="flex items-start gap-2.5 rounded-xl border p-3 text-xs"
              :class="{
                'border-emerald-200 bg-emerald-50/50': st.status === 'success',
                'border-indigo-200 bg-indigo-50/60': st.status === 'running',
                'border-rose-200 bg-rose-50/60': st.status === 'failed',
                'border-slate-200 bg-white': st.status === 'pending',
              }"
            >
              <CheckCircle2 v-if="st.status === 'success'" class="mt-0.5 h-4 w-4 shrink-0 text-emerald-600" />
              <Loader2 v-else-if="st.status === 'running'" class="mt-0.5 h-4 w-4 shrink-0 animate-spin text-indigo-600" />
              <AlertCircle v-else-if="st.status === 'failed'" class="mt-0.5 h-4 w-4 shrink-0 text-rose-600" />
              <Circle v-else class="mt-0.5 h-4 w-4 shrink-0 text-slate-300" />

              <div class="min-w-0 flex-1">
                <div class="font-semibold text-slate-800">{{ idx + 1 }}. {{ st.label }}</div>
                <div v-if="st.message" class="mt-0.5 truncate text-[11px] text-slate-500" :title="st.message">
                  {{ st.message }}
                </div>
              </div>
            </div>
          </div>

          <div
            v-if="activeJob?.error_message"
            class="rounded-lg border border-rose-200 bg-rose-50 px-3.5 py-2.5 text-xs text-rose-700"
          >
            {{ activeJob.error_message }}
          </div>

          <!-- Live Log Terminal -->
          <div class="overflow-hidden rounded-xl border border-slate-800 bg-slate-950">
            <div class="flex items-center justify-between border-b border-slate-800 px-4 py-2 text-xs text-slate-400">
              <div class="flex items-center gap-2">
                <Terminal class="h-3.5 w-3.5 text-indigo-400" />
                <span>签发过程实时日志</span>
              </div>
              <span v-if="activeJob" class="font-mono text-[11px] tabular-nums">Job #{{ activeJob.id }}</span>
            </div>
            <pre class="custom-scrollbar max-h-80 overflow-y-auto p-4 font-mono text-xs leading-6 text-slate-200 whitespace-pre-wrap">{{ liveLogs.length > 0 ? liveLogs.join('\n') : '等待日志输出...' }}</pre>
          </div>
        </div>

        <!-- Tab 3: Deployments & Logs -->
        <div v-else class="space-y-4">
          <div class="flex items-center justify-between">
            <p class="text-xs text-slate-500">
              证书签发或续期成功后将自动并发推送到以下所有已启用的目标
            </p>
            <button
              type="button"
              class="inline-flex items-center gap-1.5 rounded-lg bg-indigo-600 px-3 py-1.5 text-xs font-semibold text-white hover:bg-indigo-700"
              @click="openCreateDeployment"
            >
              <Plus class="h-3.5 w-3.5" />
              添加部署目标
            </button>
          </div>

          <div v-if="deploymentsLoading && certDeployments.length === 0" class="py-8 text-center text-sm text-slate-500">
            正在加载部署目标...
          </div>
          <div
            v-else-if="certDeployments.length === 0"
            class="rounded-xl border border-dashed border-slate-300 p-10 text-center text-xs text-slate-500"
          >
            暂未绑定任何部署目标，点击右上角「添加部署目标」关联 Caddy Docker 或本机目录
          </div>
          <div v-else class="space-y-3">
            <div
              v-for="d in certDeployments"
              :key="d.id"
              class="rounded-xl border border-slate-200 bg-white p-4 shadow-sm"
            >
              <div class="flex flex-wrap items-start justify-between gap-3">
                <div>
                  <div class="flex flex-wrap items-center gap-2">
                    <span class="text-sm font-semibold text-slate-900">{{ d.name }}</span>
                    <StatusBadge :status="d.last_status || 'pending'" />
                    <span
                      v-if="d.tls_verify_enabled && d.last_status === 'success' && !d.last_cert_fingerprint"
                      class="rounded-full bg-amber-50 px-2 py-0.5 text-[11px] font-medium text-amber-700 ring-1 ring-amber-200"
                    >
                      待 TLS 生效
                    </span>
                    <span class="rounded bg-slate-100 px-2 py-0.5 font-mono text-[11px] text-slate-600">
                      {{ d.template }}
                    </span>
                    <span v-if="!d.enabled" class="rounded bg-slate-100 px-2 py-0.5 text-[11px] text-slate-500">
                      已暂停
                    </span>
                  </div>
                  <div class="mt-1 text-xs text-slate-500">
                    目标主机: <span class="font-medium text-slate-700">{{ d.host_name || `Host #${d.host_id}` }}</span>
                    <span class="mx-1.5">·</span>
                    重载方式: <span class="font-mono">{{ d.reload_mode }}</span>
                    <span v-if="d.tls_verify_enabled" class="mx-1.5">· TLS 校验开启</span>
                  </div>
                </div>

                <div class="flex flex-wrap items-center gap-1.5">
                  <button
                    type="button"
                    :disabled="pushingDeployId === d.id"
                    class="inline-flex items-center gap-1 rounded-lg border border-indigo-200 bg-indigo-50 px-2.5 py-1.5 text-xs font-medium text-indigo-700 hover:bg-indigo-100 disabled:opacity-50"
                    @click="handlePushDeployment(d)"
                  >
                    <Send class="h-3 w-3" />
                    {{ pushingDeployId === d.id ? '推送中...' : '立即推送' }}
                  </button>
                  <button
                    type="button"
                    class="inline-flex items-center gap-1 rounded-lg border border-slate-200 px-2.5 py-1.5 text-xs font-medium text-slate-700 hover:bg-slate-50"
                    @click="openDeployLogs(d)"
                  >
                    <FileText class="h-3 w-3" />
                    日志
                  </button>
                  <button
                    type="button"
                    class="rounded-lg border border-slate-200 p-1.5 text-slate-500 hover:bg-slate-50"
                    @click="openEditDeployment(d)"
                  >
                    <Edit3 class="h-3.5 w-3.5" />
                  </button>
                  <button
                    type="button"
                    class="rounded-lg border border-rose-200 p-1.5 text-rose-500 hover:bg-rose-50"
                    @click="requestDeleteDeployment(d)"
                  >
                    <Trash2 class="h-3.5 w-3.5" />
                  </button>
                </div>
              </div>

              <div class="mt-3 space-y-1 rounded-lg bg-slate-50 p-2.5 font-mono text-[11px] text-slate-600">
                <div>Fullchain: {{ d.fullchain_path }}</div>
                <div>Privkey: {{ d.privkey_path }}</div>
                <div v-if="d.last_deployed_at" class="text-slate-400 tabular-nums">
                  最近推送: {{ formatDateTime(d.last_deployed_at) }}
                  <span v-if="d.last_cert_fingerprint">· FP: {{ truncateFingerprint(d.last_cert_fingerprint, 8) }}</span>
                </div>
                <div
                  v-if="d.last_error"
                  :class="d.last_status === 'success' ? 'text-amber-700' : 'text-rose-600'"
                >
                  {{ d.last_status === 'success' ? '提示' : '错误' }}: {{ d.last_error }}
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>
    </DrawerPanel>

    <!-- Add / Edit Deployment Modal -->
    <ModalDialog
      :open="deployModalOpen"
      :title="editingDeploy ? '编辑部署目标' : '添加部署目标'"
      subtitle="选择主机后自动推导证书目录与 Caddy --force 热重载命令"
      max-width="2xl"
      @close="deployModalOpen = false"
    >
      <div class="space-y-4">
        <div class="grid gap-4 sm:grid-cols-3">
          <div>
            <label class="mb-1 block text-xs font-medium text-slate-700">目标主机 *</label>
            <select
              v-model.number="deployForm.host_id"
              :disabled="!!editingDeploy"
              class="w-full rounded-lg border border-slate-300 bg-white px-3 py-2 text-sm disabled:bg-slate-100"
              @change="onHostOrTemplateChange"
            >
              <option v-for="h in hosts" :key="h.id" :value="h.id">
                {{ h.name }} ({{ h.is_local ? '本机' : h.host }})
              </option>
            </select>
          </div>
          <div>
            <label class="mb-1 block text-xs font-medium text-slate-700">部署模板</label>
            <select
              v-model="deployForm.template"
              class="w-full rounded-lg border border-slate-300 bg-white px-3 py-2 text-sm"
              @change="onHostOrTemplateChange"
            >
              <option value="caddy_docker">Caddy (Docker)</option>
              <option value="local_dir">本机目录输出</option>
              <option value="custom_ssh">自定义 SSH</option>
            </select>
          </div>
          <div>
            <label class="mb-1 block text-xs font-medium text-slate-700">目标名称 *</label>
            <input
              v-model="deployForm.name"
              type="text"
              class="w-full rounded-lg border border-slate-300 px-3 py-2 text-sm"
            />
          </div>
        </div>

        <div class="space-y-2.5 rounded-xl border border-slate-200 bg-slate-50 p-3.5">
          <div class="text-xs font-semibold text-slate-700">证书写入路径与权限</div>
          <div class="grid gap-3 sm:grid-cols-2">
            <div>
              <label class="mb-1 block text-[11px] font-medium text-slate-600">Fullchain 路径 *</label>
              <input v-model="deployForm.fullchain_path" type="text" class="w-full rounded border border-slate-300 bg-white px-2.5 py-1.5 font-mono text-xs" />
            </div>
            <div>
              <label class="mb-1 block text-[11px] font-medium text-slate-600">Privkey 路径 *</label>
              <input v-model="deployForm.privkey_path" type="text" class="w-full rounded border border-slate-300 bg-white px-2.5 py-1.5 font-mono text-xs" />
            </div>
            <div>
              <label class="mb-1 block text-[11px] font-medium text-slate-600">Issuer 路径（可选）</label>
              <input v-model="deployForm.issuer_path" type="text" class="w-full rounded border border-slate-300 bg-white px-2.5 py-1.5 font-mono text-xs" />
            </div>
            <div class="grid grid-cols-2 gap-2">
              <div>
                <label class="mb-1 block text-[11px] font-medium text-slate-600">证书权限</label>
                <input v-model="deployForm.cert_file_mode" type="text" class="w-full rounded border border-slate-300 bg-white px-2.5 py-1.5 font-mono text-xs" />
              </div>
              <div>
                <label class="mb-1 block text-[11px] font-medium text-slate-600">私钥权限</label>
                <input v-model="deployForm.key_file_mode" type="text" class="w-full rounded border border-slate-300 bg-white px-2.5 py-1.5 font-mono text-xs" />
              </div>
            </div>
          </div>
        </div>

        <div class="space-y-2.5 rounded-xl border border-slate-200 bg-slate-50 p-3.5">
          <div class="text-xs font-semibold text-slate-700">服务重载配置</div>
          <div class="grid gap-3 sm:grid-cols-3">
            <div>
              <label class="mb-1 block text-[11px] font-medium text-slate-600">重载模式</label>
              <select v-model="deployForm.reload_mode" class="w-full rounded border border-slate-300 bg-white px-2.5 py-1.5 text-xs">
                <option value="docker_exec">docker_exec (Caddy --force)</option>
                <option value="caddy_admin_api">caddy_admin_api</option>
                <option value="webhook">webhook</option>
                <option value="custom_cmd">custom_cmd</option>
                <option value="none">none (仅写文件)</option>
              </select>
            </div>
            <div v-if="deployForm.reload_mode === 'webhook'" class="sm:col-span-2">
              <label class="mb-1 block text-[11px] font-medium text-slate-600">Reload Webhook URL</label>
              <input
                v-model="deployForm.reload_webhook_url"
                type="url"
                placeholder="https://example.com/hooks/reload"
                class="w-full rounded border border-slate-300 bg-white px-2.5 py-1.5 font-mono text-xs"
              />
            </div>
            <div v-else-if="deployForm.reload_mode === 'caddy_admin_api'" class="sm:col-span-2">
              <label class="mb-1 block text-[11px] font-medium text-slate-600">Caddy Admin API 地址</label>
              <input
                v-model="deployForm.reload_webhook_url"
                type="url"
                placeholder="留空默认 http://127.0.0.1:2019/load"
                class="w-full rounded border border-slate-300 bg-white px-2.5 py-1.5 font-mono text-xs"
              />
            </div>
            <div v-else-if="deployForm.reload_mode !== 'none'" class="sm:col-span-2">
              <label class="mb-1 block text-[11px] font-medium text-slate-600">重载命令</label>
              <input
                v-model="deployForm.reload_command"
                type="text"
                class="w-full rounded border border-slate-300 bg-white px-2.5 py-1.5 font-mono text-xs"
              />
            </div>
          </div>
        </div>

        <div class="space-y-2.5 rounded-xl border border-slate-200 bg-slate-50 p-3.5">
          <div class="flex items-center justify-between">
            <span class="text-xs font-semibold text-slate-700">推送后 TLS 生效校验</span>
            <label class="flex cursor-pointer items-center gap-1.5 text-xs text-slate-700">
              <input v-model="deployForm.tls_verify_enabled" type="checkbox" class="rounded text-indigo-600" />
              开启指纹比对校验
            </label>
          </div>
          <div v-if="deployForm.tls_verify_enabled" class="grid gap-3 sm:grid-cols-3">
            <div>
              <label class="mb-1 block text-[11px] font-medium text-slate-600">校验主机 / IP</label>
              <input
                v-model="deployForm.tls_verify_host"
                type="text"
                :placeholder="hosts.find((h) => h.id === deployForm.host_id)?.is_local ? '留空默认连 TLS SNI 域名（或填本机 IP）' : '留空自动使用主机 IP'"
                class="w-full rounded border border-slate-300 bg-white px-2.5 py-1.5 font-mono text-xs"
              />
            </div>
            <div>
              <label class="mb-1 block text-[11px] font-medium text-slate-600">端口</label>
              <input v-model.number="deployForm.tls_verify_port" type="number" class="w-full rounded border border-slate-300 bg-white px-2.5 py-1.5 font-mono text-xs" />
            </div>
            <div>
              <label class="mb-1 block text-[11px] font-medium text-slate-600">TLS SNI</label>
              <input v-model="deployForm.tls_verify_sni" type="text" class="w-full rounded border border-slate-300 bg-white px-2.5 py-1.5 font-mono text-xs" />
            </div>
          </div>
        </div>

        <label class="flex cursor-pointer items-center gap-2 text-xs text-slate-700">
          <input v-model="deployForm.enabled" type="checkbox" class="rounded text-indigo-600" />
          启用该部署目标（自动续期成功后扇出推送）
        </label>
      </div>

      <template #footer>
        <button
          type="button"
          class="rounded-lg border border-slate-300 bg-white px-4 py-2 text-sm font-medium text-slate-700 hover:bg-slate-50"
          @click="deployModalOpen = false"
        >
          取消
        </button>
        <button
          type="button"
          :disabled="deploySaving"
          class="rounded-lg bg-indigo-600 px-4 py-2 text-sm font-semibold text-white hover:bg-indigo-700 disabled:opacity-50"
          @click="submitDeployment"
        >
          {{ deploySaving ? '保存中...' : '保存部署目标' }}
        </button>
      </template>
    </ModalDialog>

    <!-- Deploy Logs Modal -->
    <ModalDialog
      :open="logsModalOpen"
      :title="`部署推送日志 — ${logsTargetName}`"
      max-width="4xl"
      @close="logsModalOpen = false"
    >
      <div v-if="deployLogsLoading" class="flex items-center justify-center gap-2 py-10 text-sm text-slate-500">
        <RotateCw class="h-4 w-4 animate-spin text-indigo-600" />
        加载历史日志...
      </div>
      <div v-else-if="deployLogs.length === 0" class="py-10 text-center text-sm text-slate-500">
        暂无推送日志记录
      </div>
      <div v-else class="space-y-4">
        <div
          v-for="log in deployLogs"
          :key="log.id"
          class="rounded-xl border border-slate-200 bg-slate-50 p-4 text-xs"
        >
          <div class="flex flex-wrap items-center justify-between gap-2">
            <div class="flex flex-wrap items-center gap-2">
              <StatusBadge :status="log.status" />
              <span class="rounded bg-white px-2 py-0.5 font-mono text-slate-600 ring-1 ring-slate-200">
                触发: {{ log.trigger_type }}
              </span>
              <span v-if="log.exit_code !== null && log.exit_code !== undefined" class="font-mono text-slate-700">
                Exit Code: {{ log.exit_code }}
              </span>
              <span
                class="rounded px-2 py-0.5 font-medium"
                :class="log.tls_verified ? 'bg-emerald-100 text-emerald-800' : 'bg-slate-200 text-slate-600'"
              >
                TLS 校验: {{ log.tls_verified ? '通过' : '未通过/未开启' }}
              </span>
            </div>
            <span class="font-mono text-[11px] text-slate-500 tabular-nums">
              {{ formatDateTime(log.started_at) }}
            </span>
          </div>

          <div v-if="log.tls_observed_fp" class="mt-2 font-mono text-[11px] text-slate-600 break-all">
            TLS Observed FP: {{ log.tls_observed_fp }}
          </div>
          <div
            v-if="log.error_message"
            class="mt-2 rounded px-2.5 py-1.5"
            :class="log.status === 'success' ? 'bg-amber-50 text-amber-800' : 'bg-rose-50 text-rose-700'"
          >
            {{ log.error_message }}
          </div>
          <div v-if="log.stdout" class="mt-2">
            <div class="mb-1 text-[11px] font-semibold text-slate-500">STDOUT</div>
            <pre class="custom-scrollbar max-h-36 overflow-auto rounded bg-slate-900 p-2.5 font-mono text-[11px] text-emerald-300 whitespace-pre-wrap">{{ log.stdout }}</pre>
          </div>
          <div v-if="log.stderr" class="mt-2">
            <div class="mb-1 text-[11px] font-semibold text-slate-500">STDERR</div>
            <pre class="custom-scrollbar max-h-36 overflow-auto rounded bg-slate-900 p-2.5 font-mono text-[11px] text-rose-300 whitespace-pre-wrap">{{ log.stderr }}</pre>
          </div>
        </div>
      </div>
      <template #footer>
        <button
          type="button"
          class="rounded-lg border border-slate-300 bg-white px-4 py-2 text-sm font-medium text-slate-700 hover:bg-slate-50"
          @click="logsModalOpen = false"
        >
          关闭
        </button>
      </template>
    </ModalDialog>

    <!-- Private Key Copy Confirmation -->
    <ConfirmDialog
      :open="privkeyConfirmOpen"
      title="复制证书私钥 (privkey.pem)"
      message="私钥属于高敏感凭据，复制后请勿在不受信任的终端或聊天窗口粘贴留存。\n确定要复制私钥明文到剪贴板吗？"
      confirm-text="确认复制私钥"
      :loading="copyingPEM"
      @confirm="handleCopyPrivkey"
      @cancel="privkeyConfirmOpen = false"
    />

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
