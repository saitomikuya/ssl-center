<script setup lang="ts">
import { computed, onMounted, reactive, ref, watch } from 'vue'
import { useRoute } from 'vue-router'
import {
  CheckCircle2,
  Container,
  Edit3,
  FileCode2,
  FileText,
  History,
  KeyRound,
  Plus,
  RefreshCw,
  RotateCcw,
  Save,
  Send,
  Server,
  ShieldAlert,
  Sparkles,
  Terminal,
  Trash2,
  Wand2,
} from 'lucide-vue-next'
import {
  formatCaddyfile,
  getCaddyContainerInfo,
  getCaddySnapshotDiff,
  getCaddyfile,
  listCaddySnapshots,
  reloadCaddy,
  rollbackCaddySnapshot,
  saveCaddyfile,
  validateCaddyfile,
} from '@/api/caddy'
import { ApiError } from '@/api/client'
import { listDeploymentLogs, pushDeployment } from '@/api/deployments'
import {
  createHost,
  deleteHost,
  listHostDeployments,
  listHosts,
  resetHostKey,
  testHostConnection,
  updateHost,
} from '@/api/hosts'
import CaddyEditor from '@/components/ui/CaddyEditor.vue'
import ConfirmDialog from '@/components/ui/ConfirmDialog.vue'
import LineDiffViewer from '@/components/ui/LineDiffViewer.vue'
import ModalDialog from '@/components/ui/ModalDialog.vue'
import StatusBadge from '@/components/ui/StatusBadge.vue'
import { showToast } from '@/stores/toast'
import { certSubdirName, formatDateTime, truncateFingerprint } from '@/utils/format'
import type {
  CaddyConflictDetails,
  CaddyContainerInfo,
  CaddyDiffResponse,
  CaddySnapshotDTO,
  CaddyValidateErrorDetails,
  DeployLog,
  DeploymentDTO,
  HostDTO,
  HostKeyPolicy,
  HostTestResult,
} from '@/types/api'

const route = useRoute()

// ============================================================================
// Hosts List & Selection
// ============================================================================
const hosts = ref<HostDTO[]>([])
const hostsLoading = ref(false)
const selectedHostId = ref<number | null>(null)
const activeTab = ref<'info' | 'deployments' | 'caddy'>('info')

const selectedHost = computed(
  () => hosts.value.find((h) => h.id === selectedHostId.value) || null,
)

async function loadHosts(preserveSelection = true) {
  hostsLoading.value = true
  try {
    const list = await listHosts()
    hosts.value = list
    const queryHostId = Number(route.query.hostId)
    if (queryHostId && list.some((h) => h.id === queryHostId)) {
      selectedHostId.value = queryHostId
    } else if (preserveSelection && selectedHostId.value && list.some((h) => h.id === selectedHostId.value)) {
      // keep current selection
    } else if (list.length > 0) {
      selectedHostId.value = list[0].id
    } else {
      selectedHostId.value = null
    }
  } catch (err) {
    showToast('error', err instanceof Error ? err.message : '加载主机列表失败')
  } finally {
    hostsLoading.value = false
  }
}

function selectHost(host: HostDTO) {
  selectedHostId.value = host.id
}

// ============================================================================
// Create / Edit Host Modal
// ============================================================================
const hostModalOpen = ref(false)
const editingHost = ref<HostDTO | null>(null)
const hostSaving = ref(false)

const hostForm = reactive({
  name: '',
  host: '',
  port: 22,
  username: 'root',
  auth_type: 'key' as 'key' | 'password',
  ssh_private_key: '',
  ssh_passphrase: '',
  ssh_password: '',
  host_key_policy: 'tofu' as HostKeyPolicy,
  caddy_enabled: true,
  caddy_container: 'caddy',
  caddy_host_caddyfile: '/opt/caddy/Caddyfile',
  caddy_container_caddyfile: '/etc/caddy/Caddyfile',
  caddy_host_cert_dir: '/opt/caddy/certs',
  caddy_container_cert_dir: '/certs',
})

function openCreateHost() {
  editingHost.value = null
  Object.assign(hostForm, {
    name: '',
    host: '',
    port: 22,
    username: 'root',
    auth_type: 'key',
    ssh_private_key: '',
    ssh_passphrase: '',
    ssh_password: '',
    host_key_policy: 'tofu',
    caddy_enabled: true,
    caddy_container: 'caddy',
    caddy_host_caddyfile: '/opt/caddy/Caddyfile',
    caddy_container_caddyfile: '/etc/caddy/Caddyfile',
    caddy_host_cert_dir: '/opt/caddy/certs',
    caddy_container_cert_dir: '/certs',
  })
  hostModalOpen.value = true
}

function openEditHost(h: HostDTO) {
  editingHost.value = h
  Object.assign(hostForm, {
    name: h.name,
    host: h.host,
    port: h.port || 22,
    username: h.username || 'root',
    auth_type: h.auth_type === 'password' ? 'password' : 'key',
    ssh_private_key: '',
    ssh_passphrase: '',
    ssh_password: '',
    host_key_policy: (h.host_key_policy || 'tofu') as HostKeyPolicy,
    caddy_enabled: h.caddy_enabled,
    caddy_container: h.caddy_container || 'caddy',
    caddy_host_caddyfile: h.caddy_host_caddyfile || '/opt/caddy/Caddyfile',
    caddy_container_caddyfile: h.caddy_container_caddyfile || '/etc/caddy/Caddyfile',
    caddy_host_cert_dir: h.caddy_host_cert_dir || '/opt/caddy/certs',
    caddy_container_cert_dir: h.caddy_container_cert_dir || '/certs',
  })
  hostModalOpen.value = true
}

const CONTAINER_NAME_RE = /^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,127}$/

async function submitHost() {
  if (!hostForm.name.trim()) {
    showToast('warning', '请填写主机名称')
    return
  }
  if (hostForm.caddy_enabled && !CONTAINER_NAME_RE.test(hostForm.caddy_container.trim())) {
    showToast('warning', 'Caddy 容器名称格式不合法（仅支持字母、数字及 _.-）')
    return
  }

  hostSaving.value = true
  try {
    if (editingHost.value) {
      if (editingHost.value.is_local) {
        await updateHost(editingHost.value.id, {
          name: hostForm.name.trim(),
          caddy_enabled: hostForm.caddy_enabled,
          caddy_container: hostForm.caddy_container.trim(),
          caddy_host_caddyfile: hostForm.caddy_host_caddyfile.trim(),
          caddy_container_caddyfile: hostForm.caddy_container_caddyfile.trim(),
          caddy_host_cert_dir: hostForm.caddy_host_cert_dir.trim(),
          caddy_container_cert_dir: hostForm.caddy_container_cert_dir.trim(),
        })
      } else {
        await updateHost(editingHost.value.id, {
          name: hostForm.name.trim(),
          host: hostForm.host.trim(),
          port: Number(hostForm.port) || 22,
          username: hostForm.username.trim() || 'root',
          auth_type: hostForm.auth_type,
          ssh_private_key: hostForm.ssh_private_key.trim() || undefined,
          ssh_passphrase: hostForm.ssh_passphrase || undefined,
          ssh_password: hostForm.ssh_password || undefined,
          host_key_policy: hostForm.host_key_policy,
          caddy_enabled: hostForm.caddy_enabled,
          caddy_container: hostForm.caddy_container.trim(),
          caddy_host_caddyfile: hostForm.caddy_host_caddyfile.trim(),
          caddy_container_caddyfile: hostForm.caddy_container_caddyfile.trim(),
          caddy_host_cert_dir: hostForm.caddy_host_cert_dir.trim(),
          caddy_container_cert_dir: hostForm.caddy_container_cert_dir.trim(),
        })
      }
      showToast('success', '主机配置已更新')
    } else {
      if (!hostForm.host.trim()) {
        showToast('warning', '请填写主机 IP 或域名')
        hostSaving.value = false
        return
      }
      const created = await createHost({
        name: hostForm.name.trim(),
        mode: 'ssh',
        host: hostForm.host.trim(),
        port: Number(hostForm.port) || 22,
        username: hostForm.username.trim() || 'root',
        auth_type: hostForm.auth_type,
        ssh_private_key: hostForm.auth_type === 'key' ? hostForm.ssh_private_key.trim() : undefined,
        ssh_passphrase: hostForm.auth_type === 'key' ? hostForm.ssh_passphrase : undefined,
        ssh_password: hostForm.auth_type === 'password' ? hostForm.ssh_password : undefined,
        host_key_policy: hostForm.host_key_policy,
        caddy_enabled: hostForm.caddy_enabled,
        caddy_container: hostForm.caddy_container.trim(),
        caddy_host_caddyfile: hostForm.caddy_host_caddyfile.trim(),
        caddy_container_caddyfile: hostForm.caddy_container_caddyfile.trim(),
        caddy_host_cert_dir: hostForm.caddy_host_cert_dir.trim(),
        caddy_container_cert_dir: hostForm.caddy_container_cert_dir.trim(),
      })
      selectedHostId.value = created.id
      showToast('success', 'SSH 主机已添加')
    }
    hostModalOpen.value = false
    await loadHosts()
  } catch (err) {
    showToast('error', err instanceof Error ? err.message : '保存主机失败')
  } finally {
    hostSaving.value = false
  }
}

// ============================================================================
// Tab 1: SSH Test & Reset Fingerprint & Delete
// ============================================================================
const testingConn = ref(false)
const testResult = ref<HostTestResult | null>(null)
const resettingFP = ref(false)

async function handleTestConnection() {
  if (!selectedHost.value) return
  testingConn.value = true
  testResult.value = null
  try {
    const res = await testHostConnection(selectedHost.value.id)
    testResult.value = res
    if (res.ssh_ok && res.docker_ok) {
      showToast('success', '主机连接与 Docker 检测通过')
    } else {
      showToast('warning', res.message || '连接检测存在异常，请查看详情')
    }
    await loadHosts()
  } catch (err) {
    showToast('error', err instanceof Error ? err.message : '连接测试失败')
  } finally {
    testingConn.value = false
  }
}

async function handleResetFingerprint() {
  if (!selectedHost.value) return
  resettingFP.value = true
  try {
    await resetHostKey(selectedHost.value.id)
    showToast('success', 'SSH Host Key 指纹已重置，下次连接将重新信任')
    await loadHosts()
  } catch (err) {
    showToast('error', err instanceof Error ? err.message : '重置指纹失败')
  } finally {
    resettingFP.value = false
  }
}

// Delete Host
const deleteConfirmOpen = ref(false)
const deleteLoading = ref(false)

async function confirmDeleteHost() {
  if (!selectedHost.value) return
  deleteLoading.value = true
  try {
    await deleteHost(selectedHost.value.id)
    showToast('success', '主机已删除')
    deleteConfirmOpen.value = false
    selectedHostId.value = null
    await loadHosts(false)
  } catch (err) {
    if (err instanceof ApiError && err.code === 'LOCAL_HOST_PROTECTED') {
      showToast('error', '内置 Local 本机记录受保护，不允许删除')
    } else if (err instanceof ApiError && err.code === 'RESOURCE_IN_USE') {
      showToast('error', '该主机下仍有部署目标绑定，请先移除部署目标')
    } else {
      showToast('error', err instanceof Error ? err.message : '删除主机失败')
    }
  } finally {
    deleteLoading.value = false
  }
}

// ============================================================================
// Tab 2: Deployed Certificates on This Host
// ============================================================================
const hostDeployments = ref<DeploymentDTO[]>([])
const deploymentsLoading = ref(false)
const pushingId = ref<number | null>(null)
const logsModalOpen = ref(false)
const logsTargetName = ref('')
const deployLogs = ref<DeployLog[]>([])
const deployLogsLoading = ref(false)

async function loadHostDeployments(hostId: number) {
  deploymentsLoading.value = true
  try {
    hostDeployments.value = await listHostDeployments(hostId)
  } catch (err) {
    showToast('error', err instanceof Error ? err.message : '加载已部署证书失败')
  } finally {
    deploymentsLoading.value = false
  }
}

async function handleQuickPush(d: DeploymentDTO) {
  pushingId.value = d.id
  try {
    const log = await pushDeployment(d.id)
    if (log.status === 'success') {
      showToast('success', `「${d.name}」推送成功`)
    } else {
      showToast('error', `「${d.name}」推送失败: ${log.error_message || '请查看日志'}`)
    }
    if (selectedHost.value) {
      await loadHostDeployments(selectedHost.value.id)
    }
  } catch (err) {
    showToast('error', err instanceof Error ? err.message : '推送失败')
  } finally {
    pushingId.value = null
  }
}

async function openDeployLogs(d: DeploymentDTO) {
  logsTargetName.value = d.name
  logsModalOpen.value = true
  deployLogsLoading.value = true
  try {
    deployLogs.value = await listDeploymentLogs(d.id)
  } catch (err) {
    showToast('error', err instanceof Error ? err.message : '加载日志失败')
  } finally {
    deployLogsLoading.value = false
  }
}

// ============================================================================
// Tab 3: Caddyfile Workbench
// ============================================================================
const caddyEditorRef = ref<InstanceType<typeof CaddyEditor> | null>(null)
const caddyLoading = ref(false)
const caddyContent = ref('')
const expectedSHA256 = ref('')
const caddyMountType = ref('')
const caddyHostPath = ref('')
const caddySummary = ref('')
const caddyErrorLine = ref<number | null>(null)
const caddyFeedback = ref<{ ok: boolean; title: string; output: string } | null>(null)
const caddyLoadError = ref('')

const formatting = ref(false)
const validating = ref(false)
const publishing = ref(false)
const reloading = ref(false)

// 409 Conflict Diff Modal
const conflictModalOpen = ref(false)
const conflictDetails = ref<CaddyConflictDetails | null>(null)

// Snapshots Modal & Diff & Rollback
const snapshotsModalOpen = ref(false)
const snapshotsLoading = ref(false)
const snapshots = ref<CaddySnapshotDTO[]>([])
const diffModalOpen = ref(false)
const snapshotDiff = ref<CaddyDiffResponse | null>(null)
const diffLoading = ref(false)
const rollbackConfirmOpen = ref(false)
const rollbackTarget = ref<CaddySnapshotDTO | null>(null)
const rollingBack = ref(false)

// Container Info & Logs Modal
const containerModalOpen = ref(false)
const containerLoading = ref(false)
const containerInfo = ref<CaddyContainerInfo | null>(null)

async function loadCaddyfile() {
  if (!selectedHost.value || !selectedHost.value.caddy_enabled) return
  caddyLoading.value = true
  caddyLoadError.value = ''
  caddyErrorLine.value = null
  caddyFeedback.value = null
  try {
    const res = await getCaddyfile(selectedHost.value.id)
    caddyContent.value = res.content
    expectedSHA256.value = res.sha256
    caddyMountType.value = res.mount_type
    caddyHostPath.value = res.host_caddyfile_path
  } catch (err) {
    caddyLoadError.value = err instanceof Error ? err.message : '拉取远程 Caddyfile 失败'
  } finally {
    caddyLoading.value = false
  }
}

function mapHostCertPathToContainer(
  hostPath: string,
  hostRoot: string,
  containerRoot: string,
): string {
  const trimmed = hostPath.trim()
  if (!trimmed) return ''
  if (hostRoot === '/') {
    if (trimmed.startsWith('/')) {
      return containerRoot === '/' ? trimmed : `${containerRoot}${trimmed}`
    }
    return trimmed
  }
  if (trimmed === hostRoot) {
    return containerRoot
  }
  if (trimmed.startsWith(`${hostRoot}/`)) {
    const rel = trimmed.slice(hostRoot.length)
    return containerRoot === '/' ? rel : `${containerRoot}${rel}`
  }
  return trimmed
}

function buildTlsSnippet(d: DeploymentDTO): string {
  const hostRoot = (selectedHost.value?.caddy_host_cert_dir || '/opt/caddy/certs').trim().replace(/\/+$/, '') || '/'
  const certRoot = (selectedHost.value?.caddy_container_cert_dir || '/certs').trim().replace(/\/+$/, '') || '/'
  const fallbackSubdir = certSubdirName(d.cert_domain || '', d.certificate_id)
  const fallbackPrefix = certRoot === '/' ? `/${fallbackSubdir}` : `${certRoot}/${fallbackSubdir}`

  const fullchain = d.fullchain_path?.trim()
    ? mapHostCertPathToContainer(d.fullchain_path, hostRoot, certRoot)
    : `${fallbackPrefix}/fullchain.pem`
  const privkey = d.privkey_path?.trim()
    ? mapHostCertPathToContainer(d.privkey_path, hostRoot, certRoot)
    : `${fallbackPrefix}/privkey.pem`

  return `tls ${fullchain} ${privkey}`
}

function insertTlsSnippet(d: DeploymentDTO) {
  const snippet = buildTlsSnippet(d)
  caddyEditorRef.value?.insertSnippet(snippet)
  showToast('info', `已插入 ${d.cert_domain || d.name} 的 tls 配置片段`)
}

async function handleFormat() {
  if (!selectedHost.value) return
  formatting.value = true
  caddyFeedback.value = null
  try {
    const res = await formatCaddyfile(selectedHost.value.id, caddyContent.value)
    caddyContent.value = res.content
    caddyErrorLine.value = null
    showToast('success', '已完成 Caddyfile 格式化')
  } catch (err) {
    showToast('error', err instanceof Error ? err.message : '格式化失败')
  } finally {
    formatting.value = false
  }
}

async function handleValidate() {
  if (!selectedHost.value) return
  validating.value = true
  caddyErrorLine.value = null
  caddyFeedback.value = null
  try {
    const res = await validateCaddyfile(selectedHost.value.id, caddyContent.value)
    if (res.valid) {
      caddyFeedback.value = {
        ok: true,
        title: 'Caddyfile 预校验通过',
        output: res.output || 'Valid configuration',
      }
      showToast('success', '预校验通过')
    } else {
      caddyErrorLine.value = res.line || null
      caddyFeedback.value = {
        ok: false,
        title: `预校验失败${res.line ? ` (第 ${res.line} 行)` : ''}`,
        output: res.output || res.message || 'Validation failed',
      }
      showToast('error', '预校验未通过，请根据报错行修正配置')
    }
  } catch (err) {
    showToast('error', err instanceof Error ? err.message : '预校验请求失败')
  } finally {
    validating.value = false
  }
}

async function handlePublish(force = false) {
  if (!selectedHost.value) return
  publishing.value = true
  caddyErrorLine.value = null
  caddyFeedback.value = null
  try {
    const res = await saveCaddyfile(selectedHost.value.id, {
      content: caddyContent.value,
      expected_sha256: expectedSHA256.value,
      force,
      summary: caddySummary.value.trim() || (force ? '强制覆盖发布' : '在线编辑发布'),
    })
    expectedSHA256.value = res.sha256
    conflictModalOpen.value = false
    caddySummary.value = ''
    if (res.reload_ok) {
      caddyFeedback.value = {
        ok: true,
        title: '保存并热重载成功',
        output: res.output || 'Caddy reloaded successfully',
      }
      showToast('success', 'Caddyfile 已保存并热重载生效')
    } else {
      caddyFeedback.value = {
        ok: false,
        title: res.rolled_back ? '重载失败，已自动回滚至上一版本' : '保存成功但重载失败',
        output: res.output,
      }
      showToast('error', res.rolled_back ? 'Caddy 重载失败，已自动回滚保护线上服务' : '重载失败')
    }
  } catch (err) {
    if (err instanceof ApiError && err.code === 'CADDYFILE_CONFLICT') {
      conflictDetails.value = err.details as CaddyConflictDetails
      conflictModalOpen.value = true
    } else if (err instanceof ApiError && err.code === 'CADDY_VALIDATE_FAILED') {
      const details = err.details as CaddyValidateErrorDetails | undefined
      caddyErrorLine.value = details?.line || null
      caddyFeedback.value = {
        ok: false,
        title: `预校验拦截写入${details?.line ? ` (第 ${details.line} 行)` : ''}`,
        output: details?.output || details?.message || err.message,
      }
      showToast('error', '校验未通过，已阻断写入线上文件')
    } else {
      showToast('error', err instanceof Error ? err.message : '发布失败')
    }
  } finally {
    publishing.value = false
  }
}

function applyRemoteVersionFromConflict() {
  if (!conflictDetails.value) return
  caddyContent.value = conflictDetails.value.remote_content
  expectedSHA256.value = conflictDetails.value.remote_sha256
  conflictModalOpen.value = false
  showToast('info', '已刷新加载线上最新版本')
}

async function handleReloadOnly() {
  if (!selectedHost.value) return
  reloading.value = true
  try {
    const res = await reloadCaddy(selectedHost.value.id)
    caddyFeedback.value = {
      ok: res.reload_ok,
      title: res.reload_ok ? '仅重载 Caddy 成功' : '重载失败',
      output: res.output,
    }
    showToast(res.reload_ok ? 'success' : 'error', res.reload_ok ? 'Caddy 已热重载' : '重载失败')
  } catch (err) {
    showToast('error', err instanceof Error ? err.message : '重载请求失败')
  } finally {
    reloading.value = false
  }
}

async function openSnapshotsModal() {
  if (!selectedHost.value) return
  snapshotsModalOpen.value = true
  snapshotsLoading.value = true
  try {
    snapshots.value = await listCaddySnapshots(selectedHost.value.id)
  } catch (err) {
    showToast('error', err instanceof Error ? err.message : '加载历史快照失败')
  } finally {
    snapshotsLoading.value = false
  }
}

async function openSnapshotDiff(snap: CaddySnapshotDTO) {
  if (!selectedHost.value) return
  diffModalOpen.value = true
  diffLoading.value = true
  snapshotDiff.value = null
  try {
    snapshotDiff.value = await getCaddySnapshotDiff(selectedHost.value.id, snap.id)
  } catch (err) {
    diffModalOpen.value = false
    showToast('error', err instanceof Error ? err.message : '获取快照 Diff 失败')
  } finally {
    diffLoading.value = false
  }
}

function requestRollback(snap: CaddySnapshotDTO) {
  rollbackTarget.value = snap
  rollbackConfirmOpen.value = true
}

async function confirmRollback() {
  if (!selectedHost.value || !rollbackTarget.value) return
  rollingBack.value = true
  try {
    const version = rollbackTarget.value.version
    const res = await rollbackCaddySnapshot(selectedHost.value.id, rollbackTarget.value.id)
    rollbackConfirmOpen.value = false
    snapshotsModalOpen.value = false
    expectedSHA256.value = res.sha256
    await loadCaddyfile()
    const reloadOutput = res.snapshot?.reload_output || res.output
    if (res.reload_ok) {
      caddyFeedback.value = {
        ok: true,
        title: `已回滚至快照 v${version} 并重载成功`,
        output: reloadOutput || 'Caddy reloaded successfully',
      }
      showToast('success', `已回滚至快照 v${version} 并重载`)
    } else {
      caddyFeedback.value = {
        ok: false,
        title: res.rolled_back
          ? `回滚至快照 v${version} 后重载失败，已自动恢复原配置`
          : `已回滚至快照 v${version}，但 Caddy 重载失败`,
        output: reloadOutput || 'Reload failed',
      }
      showToast(
        'warning',
        reloadOutput
          ? `已回滚至快照 v${version}，但 Caddy 重载失败: ${reloadOutput}`
          : `已回滚至快照 v${version}，但 Caddy 重载失败`,
      )
    }
  } catch (err) {
    showToast('error', err instanceof Error ? err.message : '回滚失败')
  } finally {
    rollingBack.value = false
  }
}

async function openContainerModal() {
  if (!selectedHost.value) return
  containerModalOpen.value = true
  await refreshContainerInfo()
}

async function refreshContainerInfo() {
  if (!selectedHost.value) return
  containerLoading.value = true
  try {
    containerInfo.value = await getCaddyContainerInfo(selectedHost.value.id)
  } catch (err) {
    showToast('error', err instanceof Error ? err.message : '查询容器状态失败')
  } finally {
    containerLoading.value = false
  }
}

// ============================================================================
// Reactive Sync on Host or Tab Change
// ============================================================================
watch(selectedHostId, (id) => {
  testResult.value = null
  caddyContent.value = ''
  expectedSHA256.value = ''
  caddyFeedback.value = null
  caddyErrorLine.value = null
  if (!id) return
  void loadHostDeployments(id)
  if (activeTab.value === 'caddy') {
    void loadCaddyfile()
  }
})

watch(activeTab, (tab) => {
  if (!selectedHost.value) return
  if (tab === 'deployments') {
    void loadHostDeployments(selectedHost.value.id)
  } else if (tab === 'caddy') {
    void loadHostDeployments(selectedHost.value.id)
    void loadCaddyfile()
  }
})

onMounted(() => {
  void loadHosts()
})
</script>

<template>
  <div class="space-y-6">
    <!-- Header -->
    <div class="flex flex-wrap items-center justify-between gap-4">
      <div>
        <h1 class="text-2xl font-bold tracking-tight text-slate-900">主机与 Caddy</h1>
        <p class="mt-1 text-sm text-slate-500">
          管理 SSH 远程主机、内置 Local 本机、证书部署目标及 Caddyfile 在线安全编排
        </p>
      </div>
      <div class="flex items-center gap-2.5">
        <button
          type="button"
          class="inline-flex items-center gap-1.5 rounded-lg border border-slate-200 bg-white px-3.5 py-2 text-sm font-medium text-slate-700 shadow-sm hover:bg-slate-50"
          @click="loadHosts(true)"
        >
          <RefreshCw class="h-4 w-4" :class="hostsLoading ? 'animate-spin text-indigo-600' : 'text-slate-400'" />
          刷新
        </button>
        <button
          type="button"
          class="inline-flex items-center gap-1.5 rounded-lg bg-indigo-600 px-4 py-2 text-sm font-semibold text-white shadow-sm hover:bg-indigo-700"
          @click="openCreateHost"
        >
          <Plus class="h-4 w-4" />
          新建 SSH 主机
        </button>
      </div>
    </div>

    <!-- Layout: Host Cards Selector + 3-Tab Workbench -->
    <div class="grid gap-6 lg:grid-cols-12">
      <!-- Left Column: Host List Cards -->
      <div class="space-y-3 lg:col-span-4 xl:col-span-3">
        <div
          v-if="hostsLoading && hosts.length === 0"
          class="rounded-xl border border-slate-200 bg-white p-6 text-center text-sm text-slate-500"
        >
          加载主机列表...
        </div>
        <button
          v-for="h in hosts"
          :key="h.id"
          type="button"
          class="w-full rounded-xl border p-4 text-left transition"
          :class="
            selectedHostId === h.id
              ? 'border-indigo-500 bg-indigo-50/40 ring-1 ring-indigo-500/20 shadow-sm'
              : 'border-slate-200 bg-white hover:border-slate-300'
          "
          @click="selectHost(h)"
        >
          <div class="flex items-start justify-between gap-2">
            <div class="flex items-center gap-2 min-w-0">
              <Server
                class="h-4 w-4 shrink-0"
                :class="selectedHostId === h.id ? 'text-indigo-600' : 'text-slate-400'"
              />
              <span class="truncate text-sm font-semibold text-slate-900">{{ h.name }}</span>
            </div>
            <span
              v-if="h.is_local"
              class="shrink-0 rounded-full bg-indigo-100 px-2 py-0.5 text-[10px] font-semibold text-indigo-700"
            >
              内置本机
            </span>
          </div>

          <div class="mt-2 font-mono text-xs text-slate-500">
            {{ h.is_local ? 'Local Host (无 SSH)' : `${h.username}@${h.host}:${h.port}` }}
          </div>

          <div class="mt-3 flex flex-wrap items-center justify-between gap-2 text-[11px]">
            <StatusBadge v-if="h.caddy_enabled" :status="h.caddy_status || 'unknown'" />
            <span v-else class="rounded bg-slate-100 px-2 py-0.5 text-slate-500">未启用 Caddy</span>
            <span class="text-slate-500 tabular-nums">{{ h.deployment_count }} 个部署</span>
          </div>
        </button>
      </div>

      <!-- Right Column: 3-Tab Host & Caddy Workbench -->
      <div class="lg:col-span-8 xl:col-span-9">
        <div
          v-if="!selectedHost"
          class="rounded-xl border border-dashed border-slate-300 bg-white p-12 text-center text-sm text-slate-500"
        >
          请从左侧选择一台主机查看详情与 Caddy 工作台
        </div>

        <div v-else class="overflow-hidden rounded-xl border border-slate-200 bg-white shadow-sm">
          <!-- Workbench Header + Tabs -->
          <div class="border-b border-slate-200 px-6 pt-5">
            <div class="flex flex-wrap items-center justify-between gap-3">
              <div>
                <div class="flex items-center gap-2">
                  <h2 class="text-lg font-bold text-slate-900">{{ selectedHost.name }}</h2>
                  <span
                    v-if="selectedHost.is_local"
                    class="rounded-full bg-indigo-50 px-2.5 py-0.5 text-xs font-semibold text-indigo-700"
                  >
                    内置本机 (不可删除)
                  </span>
                </div>
                <p class="mt-0.5 font-mono text-xs text-slate-500">
                  {{
                    selectedHost.is_local
                      ? `容器: ${selectedHost.caddy_container || '—'} · 证书目录: ${selectedHost.caddy_host_cert_dir || '—'}`
                      : `${selectedHost.username}@${selectedHost.host}:${selectedHost.port} · 策略: ${selectedHost.host_key_policy}`
                  }}
                </p>
              </div>
              <button
                type="button"
                class="inline-flex items-center gap-1.5 rounded-lg border border-slate-200 px-3 py-1.5 text-xs font-medium text-slate-700 hover:bg-slate-50"
                @click="openEditHost(selectedHost)"
              >
                <Edit3 class="h-3.5 w-3.5" />
                编辑配置
              </button>
            </div>

            <div class="mt-4 flex gap-6">
              <button
                type="button"
                class="border-b-2 pb-3 text-xs font-semibold transition"
                :class="
                  activeTab === 'info'
                    ? 'border-indigo-600 text-indigo-600'
                    : 'border-transparent text-slate-500 hover:text-slate-800'
                "
                @click="activeTab = 'info'"
              >
                ① 主机信息与 SSH 测试
              </button>
              <button
                type="button"
                class="border-b-2 pb-3 text-xs font-semibold transition"
                :class="
                  activeTab === 'deployments'
                    ? 'border-indigo-600 text-indigo-600'
                    : 'border-transparent text-slate-500 hover:text-slate-800'
                "
                @click="activeTab = 'deployments'"
              >
                ② 已部署证书 ({{ hostDeployments.length }})
              </button>
              <button
                type="button"
                class="border-b-2 pb-3 text-xs font-semibold transition"
                :class="
                  activeTab === 'caddy'
                    ? 'border-indigo-600 text-indigo-600'
                    : 'border-transparent text-slate-500 hover:text-slate-800'
                "
                @click="activeTab = 'caddy'"
              >
                ③ Caddyfile 编辑器
              </button>
            </div>
          </div>

          <!-- Tab 1: Host Info & SSH Test -->
          <div v-if="activeTab === 'info'" class="space-y-6 p-6">
            <div class="flex flex-wrap items-center justify-between gap-3 rounded-xl border border-slate-200 bg-slate-50 p-4">
              <div>
                <div class="text-sm font-semibold text-slate-900">连通性与 Docker 环境检测</div>
                <div class="mt-0.5 text-xs text-slate-500">
                  上次检测: {{ formatDateTime(selectedHost.last_check_at) }}
                  <span v-if="selectedHost.last_check_msg">· {{ selectedHost.last_check_msg }}</span>
                </div>
              </div>
              <button
                type="button"
                :disabled="testingConn"
                class="inline-flex items-center gap-1.5 rounded-lg bg-indigo-600 px-4 py-2 text-xs font-semibold text-white hover:bg-indigo-700 disabled:opacity-50"
                @click="handleTestConnection"
              >
                <Sparkles class="h-3.5 w-3.5" />
                {{ testingConn ? '检测中...' : '测试连接' }}
              </button>
            </div>

            <!-- Live Test Result Box -->
            <div
              v-if="testResult"
              class="space-y-2 rounded-xl border p-4 text-xs"
              :class="
                testResult.ssh_ok && testResult.docker_ok
                  ? 'border-emerald-200 bg-emerald-50 text-emerald-900'
                  : 'border-amber-200 bg-amber-50 text-amber-900'
              "
            >
              <div class="flex flex-wrap items-center gap-3 font-semibold">
                <span>SSH/本机: {{ testResult.ssh_ok ? '正常' : '失败' }}</span>
                <span>Docker: {{ testResult.docker_ok ? '可用' : '不可用' }}</span>
                <span>Caddy 容器: {{ testResult.caddy_running ? '运行中' : '未运行' }}</span>
                <span v-if="testResult.caddy_version" class="font-mono">({{ testResult.caddy_version }})</span>
              </div>
              <div v-if="testResult.host_key_fingerprint" class="font-mono text-[11px] break-all">
                Host Key ({{ testResult.host_key_status }}): {{ testResult.host_key_fingerprint }}
              </div>
              <div>{{ testResult.message }}</div>
            </div>

            <div class="grid gap-4 sm:grid-cols-2">
              <!-- SSH & Host Key Card -->
              <div class="rounded-xl border border-slate-200 p-4">
                <div class="mb-3 flex items-center gap-2 text-xs font-semibold uppercase tracking-wider text-slate-500">
                  <KeyRound class="h-4 w-4 text-slate-400" />
                  连接与 SSH Host Key
                </div>
                <dl class="space-y-2 text-xs">
                  <div class="flex justify-between">
                    <dt class="text-slate-400">模式</dt>
                    <dd class="font-mono font-medium">{{ selectedHost.mode }}</dd>
                  </div>
                  <template v-if="!selectedHost.is_local">
                    <div class="flex justify-between">
                      <dt class="text-slate-400">认证方式</dt>
                      <dd class="font-mono">{{ selectedHost.auth_type }}</dd>
                    </div>
                    <div class="flex justify-between">
                      <dt class="text-slate-400">Host Key 策略</dt>
                      <dd class="font-mono uppercase">{{ selectedHost.host_key_policy }}</dd>
                    </div>
                    <div>
                      <dt class="text-slate-400">已锁定公钥指纹</dt>
                      <dd class="mt-1 rounded bg-slate-50 p-2 font-mono text-[11px] text-slate-700 break-all">
                        {{ selectedHost.host_key_fingerprint || '尚未锁定（首次连接 TOFU 自动记录）' }}
                      </dd>
                    </div>
                  </template>
                </dl>

                <div v-if="!selectedHost.is_local" class="mt-3 flex justify-end">
                  <button
                    type="button"
                    :disabled="resettingFP || !selectedHost.host_key_fingerprint"
                    class="inline-flex items-center gap-1 rounded-lg border border-slate-200 px-2.5 py-1.5 text-xs font-medium text-slate-700 hover:bg-slate-50 disabled:opacity-50"
                    @click="handleResetFingerprint"
                  >
                    <RotateCcw class="h-3.5 w-3.5" />
                    重置 Host Key 指纹
                  </button>
                </div>
              </div>

              <!-- Caddy Docker Profile Card -->
              <div class="rounded-xl border border-slate-200 p-4">
                <div class="mb-3 flex items-center gap-2 text-xs font-semibold uppercase tracking-wider text-slate-500">
                  <Container class="h-4 w-4 text-slate-400" />
                  Caddy Docker 档案
                </div>
                <dl class="space-y-2 text-xs">
                  <div class="flex justify-between">
                    <dt class="text-slate-400">启用状态</dt>
                    <dd>{{ selectedHost.caddy_enabled ? '已启用' : '已关闭' }}</dd>
                  </div>
                  <div class="flex justify-between gap-2">
                    <dt class="text-slate-400">容器名</dt>
                    <dd class="font-mono font-medium">{{ selectedHost.caddy_container || '—' }}</dd>
                  </div>
                  <div class="flex justify-between gap-2">
                    <dt class="shrink-0 text-slate-400">宿主机 Caddyfile</dt>
                    <dd class="truncate font-mono text-[11px]" :title="selectedHost.caddy_host_caddyfile">
                      {{ selectedHost.caddy_host_caddyfile || '—' }}
                    </dd>
                  </div>
                  <div class="flex justify-between gap-2">
                    <dt class="shrink-0 text-slate-400">容器内 Caddyfile</dt>
                    <dd class="truncate font-mono text-[11px]" :title="selectedHost.caddy_container_caddyfile">
                      {{ selectedHost.caddy_container_caddyfile || '—' }}
                    </dd>
                  </div>
                  <div class="flex justify-between gap-2">
                    <dt class="shrink-0 text-slate-400">宿主机证书目录</dt>
                    <dd class="truncate font-mono text-[11px]" :title="selectedHost.caddy_host_cert_dir">
                      {{ selectedHost.caddy_host_cert_dir || '—' }}
                    </dd>
                  </div>
                  <div class="flex justify-between gap-2">
                    <dt class="shrink-0 text-slate-400">容器内证书目录</dt>
                    <dd class="truncate font-mono text-[11px]" :title="selectedHost.caddy_container_cert_dir">
                      {{ selectedHost.caddy_container_cert_dir || '—' }}
                    </dd>
                  </div>
                </dl>
              </div>
            </div>

            <!-- Danger Zone -->
            <div class="flex items-center justify-between rounded-xl border border-rose-100 bg-rose-50/40 p-4">
              <div>
                <div class="text-xs font-semibold text-rose-900">删除主机</div>
                <div class="text-xs text-rose-700/80">
                  {{
                    selectedHost.is_local
                      ? '内置 Local 主机受系统保护，不可删除'
                      : '删除前需先移除该主机关联的所有证书部署目标'
                  }}
                </div>
              </div>
              <button
                type="button"
                :disabled="selectedHost.is_local"
                class="inline-flex items-center gap-1.5 rounded-lg border border-rose-200 bg-white px-3 py-1.5 text-xs font-semibold text-rose-600 hover:bg-rose-50 disabled:cursor-not-allowed disabled:opacity-40"
                @click="deleteConfirmOpen = true"
              >
                <Trash2 class="h-3.5 w-3.5" />
                删除主机
              </button>
            </div>
          </div>

          <!-- Tab 2: Deployed Certificates -->
          <div v-else-if="activeTab === 'deployments'" class="p-6">
            <div v-if="deploymentsLoading && hostDeployments.length === 0" class="py-10 text-center text-sm text-slate-500">
              加载该主机的部署记录...
            </div>
            <div
              v-else-if="hostDeployments.length === 0"
              class="rounded-xl border border-dashed border-slate-300 p-10 text-center text-xs text-slate-500"
            >
              暂无证书绑定到该主机。请前往「证书管理」为目标证书添加部署目标。
            </div>
            <div v-else class="space-y-3">
              <div
                v-for="d in hostDeployments"
                :key="d.id"
                class="rounded-xl border border-slate-200 p-4"
              >
                <div class="flex flex-wrap items-center justify-between gap-3">
                  <div>
                    <div class="flex flex-wrap items-center gap-2">
                      <span class="text-sm font-semibold text-slate-900">{{ d.cert_domain || `Cert #${d.certificate_id}` }}</span>
                      <span class="text-xs text-slate-500">({{ d.name }})</span>
                      <StatusBadge :status="d.last_status || 'pending'" />
                    </div>
                    <div class="mt-1 font-mono text-[11px] text-slate-500">
                      {{ d.fullchain_path }}
                    </div>
                    <div class="mt-1 text-[11px] text-slate-400 tabular-nums">
                      最近推送: {{ formatDateTime(d.last_deployed_at) }}
                      <span v-if="d.last_cert_fingerprint">· FP: {{ truncateFingerprint(d.last_cert_fingerprint, 8) }}</span>
                    </div>
                    <div v-if="d.last_error" class="mt-1 text-xs text-rose-600">{{ d.last_error }}</div>
                  </div>
                  <div class="flex items-center gap-2">
                    <button
                      type="button"
                      :disabled="pushingId === d.id"
                      class="inline-flex items-center gap-1 rounded-lg border border-indigo-200 bg-indigo-50 px-2.5 py-1.5 text-xs font-medium text-indigo-700 hover:bg-indigo-100 disabled:opacity-50"
                      @click="handleQuickPush(d)"
                    >
                      <Send class="h-3 w-3" />
                      {{ pushingId === d.id ? '推送中...' : '立即推送' }}
                    </button>
                    <button
                      type="button"
                      class="inline-flex items-center gap-1 rounded-lg border border-slate-200 px-2.5 py-1.5 text-xs font-medium text-slate-700 hover:bg-slate-50"
                      @click="openDeployLogs(d)"
                    >
                      <FileText class="h-3 w-3" />
                      日志
                    </button>
                  </div>
                </div>
              </div>
            </div>
          </div>

          <!-- Tab 3: Caddyfile Editor Workbench -->
          <div v-else class="p-6">
            <div
              v-if="!selectedHost.caddy_enabled"
              class="rounded-xl border border-dashed border-slate-300 p-10 text-center text-sm text-slate-500"
            >
              该主机尚未启用「Caddy Docker 档案」，请点击右上角「编辑配置」开启后使用在线工作台。
            </div>

            <div v-else class="space-y-4">
              <!-- Toolbar -->
              <div class="flex flex-wrap items-center justify-between gap-2 rounded-xl border border-slate-200 bg-slate-50 p-3">
                <div class="flex flex-wrap items-center gap-2">
                  <button
                    type="button"
                    :disabled="caddyLoading"
                    class="inline-flex items-center gap-1.5 rounded-lg border border-slate-200 bg-white px-2.5 py-1.5 text-xs font-medium text-slate-700 hover:bg-slate-50"
                    @click="loadCaddyfile"
                  >
                    <RefreshCw class="h-3.5 w-3.5" :class="caddyLoading ? 'animate-spin' : ''" />
                    拉取线上
                  </button>
                  <button
                    type="button"
                    :disabled="formatting || caddyLoading"
                    class="inline-flex items-center gap-1.5 rounded-lg border border-slate-200 bg-white px-2.5 py-1.5 text-xs font-medium text-slate-700 hover:bg-slate-50 disabled:opacity-50"
                    @click="handleFormat"
                  >
                    <Wand2 class="h-3.5 w-3.5" />
                    {{ formatting ? '格式化中...' : '格式化 (fmt)' }}
                  </button>
                  <button
                    type="button"
                    :disabled="validating || caddyLoading"
                    class="inline-flex items-center gap-1.5 rounded-lg border border-slate-200 bg-white px-2.5 py-1.5 text-xs font-medium text-slate-700 hover:bg-slate-50 disabled:opacity-50"
                    @click="handleValidate"
                  >
                    <CheckCircle2 class="h-3.5 w-3.5 text-emerald-600" />
                    {{ validating ? '校验中...' : '预校验 (validate)' }}
                  </button>
                  <button
                    type="button"
                    :disabled="reloading"
                    class="inline-flex items-center gap-1.5 rounded-lg border border-slate-200 bg-white px-2.5 py-1.5 text-xs font-medium text-slate-700 hover:bg-slate-50 disabled:opacity-50"
                    @click="handleReloadOnly"
                  >
                    <RotateCcw class="h-3.5 w-3.5 text-sky-600" />
                    仅重载 Caddy
                  </button>
                </div>

                <div class="flex flex-wrap items-center gap-2">
                  <button
                    type="button"
                    class="inline-flex items-center gap-1.5 rounded-lg border border-slate-200 bg-white px-2.5 py-1.5 text-xs font-medium text-slate-700 hover:bg-slate-50"
                    @click="openSnapshotsModal"
                  >
                    <History class="h-3.5 w-3.5 text-slate-500" />
                    历史快照
                  </button>
                  <button
                    type="button"
                    class="inline-flex items-center gap-1.5 rounded-lg border border-slate-200 bg-white px-2.5 py-1.5 text-xs font-medium text-slate-700 hover:bg-slate-50"
                    @click="openContainerModal"
                  >
                    <Terminal class="h-3.5 w-3.5 text-slate-500" />
                    容器状态与日志
                  </button>
                  <button
                    type="button"
                    :disabled="publishing || caddyLoading"
                    class="inline-flex items-center gap-1.5 rounded-lg bg-indigo-600 px-3.5 py-1.5 text-xs font-semibold text-white shadow-sm hover:bg-indigo-700 disabled:opacity-50"
                    @click="handlePublish(false)"
                  >
                    <Save class="h-3.5 w-3.5" />
                    {{ publishing ? '发布中...' : '保存并重载 (⌘S)' }}
                  </button>
                </div>
              </div>

              <!-- Meta info + Summary input -->
              <div class="flex flex-wrap items-center justify-between gap-3 text-xs text-slate-500">
                <div class="flex flex-wrap items-center gap-2 font-mono text-[11px]">
                  <span>路径: {{ caddyHostPath || selectedHost.caddy_host_caddyfile }}</span>
                  <span v-if="caddyMountType" class="rounded bg-slate-100 px-1.5 py-0.5 text-slate-700">
                    挂载: {{ caddyMountType }}
                  </span>
                  <span v-if="expectedSHA256" class="text-slate-400">
                    SHA256: {{ expectedSHA256.slice(0, 12) }}
                  </span>
                </div>
                <input
                  v-model="caddySummary"
                  type="text"
                  placeholder="本次变更备注（可选，写入快照历史）"
                  class="w-full rounded-lg border border-slate-200 px-3 py-1 text-xs focus:border-indigo-500 focus:outline-none sm:w-64"
                />
              </div>

              <div
                v-if="caddyLoadError"
                class="rounded-xl border border-rose-200 bg-rose-50 p-4 text-xs text-rose-700"
              >
                <div class="font-semibold">拉取 Caddyfile 失败</div>
                <div class="mt-1">{{ caddyLoadError }}</div>
              </div>

              <!-- Feedback Banner (validate / reload / rollback) -->
              <div
                v-if="caddyFeedback"
                class="rounded-xl border p-3.5 text-xs"
                :class="
                  caddyFeedback.ok
                    ? 'border-emerald-200 bg-emerald-50 text-emerald-900'
                    : 'border-rose-200 bg-rose-50 text-rose-900'
                "
              >
                <div class="font-semibold">{{ caddyFeedback.title }}</div>
                <pre
                  v-if="caddyFeedback.output"
                  class="mt-1.5 max-h-36 overflow-auto whitespace-pre-wrap font-mono text-[11px]"
                >{{ caddyFeedback.output }}</pre>
              </div>

              <!-- Editor + Deployed Certs TLS Snippet Picker -->
              <div class="grid gap-4 xl:grid-cols-12">
                <div class="h-[480px] xl:col-span-8">
                  <CaddyEditor
                    ref="caddyEditorRef"
                    v-model="caddyContent"
                    :error-line="caddyErrorLine"
                    @save="handlePublish(false)"
                  />
                </div>

                <div class="flex flex-col rounded-xl border border-slate-200 bg-slate-50/70 p-4 xl:col-span-4">
                  <div class="mb-3 flex items-center gap-2">
                    <FileCode2 class="h-4 w-4 text-indigo-600" />
                    <div>
                      <h3 class="text-xs font-semibold text-slate-900">已部署到本机的证书</h3>
                      <p class="text-[11px] text-slate-500">点击在光标处一键插入 tls 片段</p>
                    </div>
                  </div>

                  <div
                    v-if="hostDeployments.length === 0"
                    class="flex flex-1 items-center justify-center rounded-lg border border-dashed border-slate-300 p-4 text-center text-xs text-slate-400"
                  >
                    暂无绑定到本机的证书
                  </div>
                  <div v-else class="custom-scrollbar max-h-[400px] space-y-2 overflow-y-auto pr-1">
                    <div
                      v-for="d in hostDeployments"
                      :key="d.id"
                      class="rounded-lg border border-slate-200 bg-white p-3"
                    >
                      <div class="flex items-center justify-between gap-2">
                        <span class="truncate text-xs font-semibold text-slate-800">
                          {{ d.cert_domain || d.name }}
                        </span>
                        <button
                          type="button"
                          class="shrink-0 rounded bg-indigo-50 px-2 py-1 text-[11px] font-semibold text-indigo-700 hover:bg-indigo-100"
                          @click="insertTlsSnippet(d)"
                        >
                          插入 tls
                        </button>
                      </div>
                      <div class="mt-1.5 rounded bg-slate-50 p-1.5 font-mono text-[10px] text-slate-500 break-all">
                        {{ buildTlsSnippet(d) }}
                      </div>
                    </div>
                  </div>
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>

    <!-- Create / Edit Host Modal -->
    <ModalDialog
      :open="hostModalOpen"
      :title="editingHost ? `编辑主机 — ${editingHost.name}` : '新建 SSH 主机'"
      subtitle="编辑时 SSH 密钥/密码留空表示保留原加密值不变"
      max-width="2xl"
      @close="hostModalOpen = false"
    >
      <div class="space-y-4">
        <div class="grid gap-4 sm:grid-cols-2">
          <div>
            <label class="mb-1 block text-xs font-medium text-slate-700">主机名称 *</label>
            <input
              v-model="hostForm.name"
              type="text"
              placeholder="例如：edge-hk-1"
              class="w-full rounded-lg border border-slate-300 px-3 py-2 text-sm focus:border-indigo-500 focus:outline-none"
            />
          </div>
          <template v-if="!editingHost?.is_local">
            <div>
              <label class="mb-1 block text-xs font-medium text-slate-700">主机 IP / 域名 *</label>
              <input
                v-model="hostForm.host"
                type="text"
                placeholder="10.0.0.10"
                class="w-full rounded-lg border border-slate-300 px-3 py-2 font-mono text-sm focus:border-indigo-500 focus:outline-none"
              />
            </div>
          </template>
        </div>

        <template v-if="!editingHost?.is_local">
          <div class="grid gap-4 sm:grid-cols-3">
            <div>
              <label class="mb-1 block text-xs font-medium text-slate-700">SSH 端口</label>
              <input
                v-model.number="hostForm.port"
                type="number"
                class="w-full rounded-lg border border-slate-300 px-3 py-2 font-mono text-sm tabular-nums"
              />
            </div>
            <div>
              <label class="mb-1 block text-xs font-medium text-slate-700">用户名</label>
              <input
                v-model="hostForm.username"
                type="text"
                class="w-full rounded-lg border border-slate-300 px-3 py-2 font-mono text-sm"
              />
            </div>
            <div>
              <label class="mb-1 block text-xs font-medium text-slate-700">Host Key 策略</label>
              <select
                v-model="hostForm.host_key_policy"
                class="w-full rounded-lg border border-slate-300 bg-white px-3 py-2 text-sm"
              >
                <option value="tofu">TOFU (首次信任锁定)</option>
                <option value="strict">Strict (严格比对)</option>
                <option value="insecure">Insecure (跳过校验)</option>
              </select>
            </div>
          </div>

          <div class="space-y-3 rounded-xl border border-slate-200 bg-slate-50 p-4">
            <div class="flex items-center gap-4 text-xs font-medium">
              <label class="flex cursor-pointer items-center gap-1.5">
                <input v-model="hostForm.auth_type" type="radio" value="key" class="text-indigo-600" />
                SSH 私钥认证
              </label>
              <label class="flex cursor-pointer items-center gap-1.5">
                <input v-model="hostForm.auth_type" type="radio" value="password" class="text-indigo-600" />
                SSH 密码认证
              </label>
            </div>

            <template v-if="hostForm.auth_type === 'key'">
              <div>
                <label class="mb-1 block text-xs font-medium text-slate-700">
                  SSH 私钥 (OpenSSH / PEM) {{ editingHost ? '（留空保持原私钥）' : '' }}
                </label>
                <textarea
                  v-model="hostForm.ssh_private_key"
                  rows="3"
                  placeholder="-----BEGIN OPENSSH PRIVATE KEY-----"
                  class="w-full rounded-lg border border-slate-300 bg-white px-3 py-2 font-mono text-xs"
                />
              </div>
              <div>
                <label class="mb-1 block text-xs font-medium text-slate-700">私钥口令 Passphrase（可选）</label>
                <input
                  v-model="hostForm.ssh_passphrase"
                  type="password"
                  placeholder="如私钥无密码请留空"
                  class="w-full rounded-lg border border-slate-300 bg-white px-3 py-2 font-mono text-xs"
                />
              </div>
            </template>

            <div v-else>
              <label class="mb-1 block text-xs font-medium text-slate-700">
                SSH 登录密码 {{ editingHost ? '（留空保持原密码）' : '' }}
              </label>
              <input
                v-model="hostForm.ssh_password"
                type="password"
                class="w-full rounded-lg border border-slate-300 bg-white px-3 py-2 font-mono text-xs"
              />
            </div>
          </div>
        </template>

        <!-- Caddy Docker Profile -->
        <div class="space-y-3 rounded-xl border border-slate-200 bg-slate-50 p-4">
          <div class="flex items-center justify-between">
            <span class="text-xs font-semibold text-slate-800">Caddy Docker 档案</span>
            <label class="flex cursor-pointer items-center gap-1.5 text-xs text-slate-700">
              <input v-model="hostForm.caddy_enabled" type="checkbox" class="rounded text-indigo-600" />
              启用 Caddy 管理工作台
            </label>
          </div>
          <div v-if="hostForm.caddy_enabled" class="grid gap-3 sm:grid-cols-2">
            <div class="sm:col-span-2">
              <label class="mb-1 block text-[11px] font-medium text-slate-600">容器名称</label>
              <input v-model="hostForm.caddy_container" type="text" class="w-full rounded border border-slate-300 bg-white px-2.5 py-1.5 font-mono text-xs" />
            </div>
            <div>
              <label class="mb-1 block text-[11px] font-medium text-slate-600">宿主机 Caddyfile 路径</label>
              <input v-model="hostForm.caddy_host_caddyfile" type="text" class="w-full rounded border border-slate-300 bg-white px-2.5 py-1.5 font-mono text-xs" />
            </div>
            <div>
              <label class="mb-1 block text-[11px] font-medium text-slate-600">容器内 Caddyfile 路径</label>
              <input v-model="hostForm.caddy_container_caddyfile" type="text" class="w-full rounded border border-slate-300 bg-white px-2.5 py-1.5 font-mono text-xs" />
            </div>
            <div>
              <label class="mb-1 block text-[11px] font-medium text-slate-600">宿主机证书根目录</label>
              <input v-model="hostForm.caddy_host_cert_dir" type="text" class="w-full rounded border border-slate-300 bg-white px-2.5 py-1.5 font-mono text-xs" />
            </div>
            <div>
              <label class="mb-1 block text-[11px] font-medium text-slate-600">容器内证书挂载根目录</label>
              <input v-model="hostForm.caddy_container_cert_dir" type="text" class="w-full rounded border border-slate-300 bg-white px-2.5 py-1.5 font-mono text-xs" />
            </div>
          </div>
        </div>
      </div>

      <template #footer>
        <button
          type="button"
          class="rounded-lg border border-slate-300 bg-white px-4 py-2 text-sm font-medium text-slate-700 hover:bg-slate-50"
          @click="hostModalOpen = false"
        >
          取消
        </button>
        <button
          type="button"
          :disabled="hostSaving"
          class="rounded-lg bg-indigo-600 px-4 py-2 text-sm font-semibold text-white hover:bg-indigo-700 disabled:opacity-50"
          @click="submitHost"
        >
          {{ hostSaving ? '保存中...' : '保存主机' }}
        </button>
      </template>
    </ModalDialog>

    <!-- 409 Conflict Diff Modal -->
    <ModalDialog
      :open="conflictModalOpen"
      title="检测到 Caddyfile 外部变更冲突 (409 Conflict)"
      subtitle="线上文件在您加载后已被外部修改，请对比差异后选择处理方式"
      max-width="5xl"
      @close="conflictModalOpen = false"
    >
      <div v-if="conflictDetails" class="space-y-4">
        <div class="flex items-start gap-3 rounded-xl border border-amber-200 bg-amber-50 p-3.5 text-xs text-amber-800">
          <ShieldAlert class="mt-0.5 h-5 w-5 shrink-0 text-amber-600" />
          <div class="space-y-1 font-mono">
            <div>加载时 SHA-256: {{ conflictDetails.expected_sha256 }}</div>
            <div>线上最新 SHA-256: {{ conflictDetails.remote_sha256 }}</div>
          </div>
        </div>

        <LineDiffViewer
          :old-text="conflictDetails.remote_content"
          :new-text="caddyContent"
          old-label="线上最新版本"
          new-label="本地编辑草稿"
        />
      </div>

      <template #footer>
        <button
          type="button"
          class="rounded-lg border border-slate-300 bg-white px-4 py-2 text-sm font-medium text-slate-700 hover:bg-slate-50"
          @click="conflictModalOpen = false"
        >
          继续编辑草稿
        </button>
        <button
          type="button"
          class="rounded-lg border border-indigo-200 bg-indigo-50 px-4 py-2 text-sm font-medium text-indigo-700 hover:bg-indigo-100"
          @click="applyRemoteVersionFromConflict"
        >
          刷新加载线上版本
        </button>
        <button
          type="button"
          :disabled="publishing"
          class="rounded-lg bg-rose-600 px-4 py-2 text-sm font-semibold text-white hover:bg-rose-700 disabled:opacity-50"
          @click="handlePublish(true)"
        >
          {{ publishing ? '覆盖中...' : '强制覆盖发布' }}
        </button>
      </template>
    </ModalDialog>

    <!-- Snapshots History Modal -->
    <ModalDialog
      :open="snapshotsModalOpen"
      title="Caddyfile 历史快照与回滚"
      max-width="4xl"
      @close="snapshotsModalOpen = false"
    >
      <div v-if="snapshotsLoading" class="py-10 text-center text-sm text-slate-500">
        正在加载历史快照...
      </div>
      <div v-else-if="snapshots.length === 0" class="py-10 text-center text-sm text-slate-500">
        暂无历史快照记录
      </div>
      <div v-else class="overflow-x-auto">
        <table class="min-w-full divide-y divide-slate-200 text-left text-xs">
          <thead class="bg-slate-50 font-semibold text-slate-500">
            <tr>
              <th class="px-3 py-2.5">版本</th>
              <th class="px-3 py-2.5">动作 / 备注</th>
              <th class="px-3 py-2.5">重载结果</th>
              <th class="px-3 py-2.5">时间</th>
              <th class="px-3 py-2.5 text-right">操作</th>
            </tr>
          </thead>
          <tbody class="divide-y divide-slate-100">
            <tr v-for="s in snapshots" :key="s.id" class="hover:bg-slate-50">
              <td class="px-3 py-3 font-mono font-semibold text-slate-800">v{{ s.version }}</td>
              <td class="px-3 py-3">
                <div class="font-medium text-slate-800">{{ s.summary || '—' }}</div>
                <div class="font-mono text-[11px] text-slate-400">{{ s.action }} · {{ s.sha256.slice(0, 10) }}</div>
              </td>
              <td class="px-3 py-3">
                <StatusBadge :status="s.reload_ok ? 'success' : 'failed'" :label="s.reload_ok ? '重载成功' : '重载失败'" />
              </td>
              <td class="px-3 py-3 font-mono text-slate-500 tabular-nums">{{ formatDateTime(s.created_at) }}</td>
              <td class="px-3 py-3 text-right">
                <div class="inline-flex gap-1.5">
                  <button
                    type="button"
                    class="rounded border border-slate-200 px-2.5 py-1 font-medium text-slate-700 hover:bg-slate-100"
                    @click="openSnapshotDiff(s)"
                  >
                    查看 Diff
                  </button>
                  <button
                    type="button"
                    class="rounded border border-indigo-200 bg-indigo-50 px-2.5 py-1 font-medium text-indigo-700 hover:bg-indigo-100"
                    @click="requestRollback(s)"
                  >
                    一键回滚
                  </button>
                </div>
              </td>
            </tr>
          </tbody>
        </table>
      </div>
      <template #footer>
        <button
          type="button"
          class="rounded-lg border border-slate-300 bg-white px-4 py-2 text-sm font-medium text-slate-700 hover:bg-slate-50"
          @click="snapshotsModalOpen = false"
        >
          关闭
        </button>
      </template>
    </ModalDialog>

    <!-- Snapshot Diff Modal -->
    <ModalDialog
      :open="diffModalOpen"
      :title="`快照差异对比 — ${snapshotDiff ? `v${snapshotDiff.version}` : ''}`"
      max-width="5xl"
      @close="diffModalOpen = false"
    >
      <div v-if="diffLoading" class="py-10 text-center text-sm text-slate-500">
        正在计算差异...
      </div>
      <div v-else-if="snapshotDiff" class="space-y-4">
        <LineDiffViewer
          :old-text="snapshotDiff.snapshot_content"
          :new-text="snapshotDiff.current_content"
          :old-label="`历史快照 v${snapshotDiff.version}`"
          new-label="当前线上版本"
        />
      </div>
      <template #footer>
        <button
          type="button"
          class="rounded-lg border border-slate-300 bg-white px-4 py-2 text-sm font-medium text-slate-700 hover:bg-slate-50"
          @click="diffModalOpen = false"
        >
          关闭
        </button>
      </template>
    </ModalDialog>

    <!-- Container Status & Logs Modal -->
    <ModalDialog
      :open="containerModalOpen"
      :title="`Caddy 容器状态与日志 — ${selectedHost?.caddy_container || ''}`"
      max-width="4xl"
      @close="containerModalOpen = false"
    >
      <div v-if="containerLoading && !containerInfo" class="py-10 text-center text-sm text-slate-500">
        正在执行 docker inspect 与 logs...
      </div>
      <div v-else-if="containerInfo" class="space-y-4">
        <div class="grid gap-3 rounded-xl border border-slate-200 bg-slate-50 p-4 text-xs sm:grid-cols-2">
          <div><span class="text-slate-400">运行状态：</span><StatusBadge :status="containerInfo.running ? 'running' : 'stopped'" :label="containerInfo.status" /></div>
          <div><span class="text-slate-400">镜像：</span><span class="font-mono">{{ containerInfo.image }}</span></div>
          <div><span class="text-slate-400">挂载模式：</span><span class="font-mono">{{ containerInfo.mount_type }}</span></div>
          <div><span class="text-slate-400">检测时间：</span><span class="font-mono tabular-nums">{{ formatDateTime(containerInfo.inspected_at) }}</span></div>
          <div v-if="containerInfo.mounts && containerInfo.mounts.length > 0" class="sm:col-span-2">
            <div class="text-slate-400">挂载点列表：</div>
            <div class="mt-1 space-y-0.5 font-mono text-[11px] text-slate-600">
              <div v-for="m in containerInfo.mounts" :key="m">{{ m }}</div>
            </div>
          </div>
        </div>

        <div class="overflow-hidden rounded-xl border border-slate-800 bg-slate-950">
          <div class="flex items-center justify-between border-b border-slate-800 px-4 py-2 text-xs text-slate-400">
            <span>docker logs (最近输出)</span>
            <button
              type="button"
              :disabled="containerLoading"
              class="inline-flex items-center gap-1 text-indigo-400 hover:text-indigo-300"
              @click="refreshContainerInfo"
            >
              <RefreshCw class="h-3 w-3" :class="containerLoading ? 'animate-spin' : ''" />
              刷新日志
            </button>
          </div>
          <pre class="custom-scrollbar max-h-80 overflow-auto p-4 font-mono text-xs leading-5 text-slate-200 whitespace-pre-wrap">{{ containerInfo.logs || '暂无日志输出' }}</pre>
        </div>
      </div>
      <template #footer>
        <button
          type="button"
          class="rounded-lg border border-slate-300 bg-white px-4 py-2 text-sm font-medium text-slate-700 hover:bg-slate-50"
          @click="containerModalOpen = false"
        >
          关闭
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
      <div v-if="deployLogsLoading" class="py-10 text-center text-sm text-slate-500">
        加载历史日志...
      </div>
      <div v-else-if="deployLogs.length === 0" class="py-10 text-center text-sm text-slate-500">
        暂无推送日志记录
      </div>
      <div v-else class="space-y-4">
        <div v-for="log in deployLogs" :key="log.id" class="rounded-xl border border-slate-200 bg-slate-50 p-4 text-xs">
          <div class="flex flex-wrap items-center justify-between gap-2">
            <div class="flex items-center gap-2">
              <StatusBadge :status="log.status" />
              <span v-if="log.exit_code !== null && log.exit_code !== undefined" class="font-mono">
                Exit Code: {{ log.exit_code }}
              </span>
              <span class="rounded px-2 py-0.5" :class="log.tls_verified ? 'bg-emerald-100 text-emerald-800' : 'bg-slate-200 text-slate-600'">
                TLS 校验: {{ log.tls_verified ? '通过' : '未通过/未开启' }}
              </span>
            </div>
            <span class="font-mono text-[11px] text-slate-500 tabular-nums">{{ formatDateTime(log.started_at) }}</span>
          </div>
          <div v-if="log.error_message" class="mt-2 rounded bg-rose-50 px-2.5 py-1.5 text-rose-700">{{ log.error_message }}</div>
          <pre v-if="log.stdout" class="mt-2 max-h-32 overflow-auto rounded bg-slate-900 p-2 font-mono text-[11px] text-emerald-300">{{ log.stdout }}</pre>
          <pre v-if="log.stderr" class="mt-2 max-h-32 overflow-auto rounded bg-slate-900 p-2 font-mono text-[11px] text-rose-300">{{ log.stderr }}</pre>
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

    <!-- Rollback Confirmation -->
    <ConfirmDialog
      :open="rollbackConfirmOpen"
      title="确认回滚 Caddyfile"
      :message="`确定要将线上 Caddyfile 回滚至历史快照 v${rollbackTarget?.version ?? ''} 吗？\n系统将重新校验并执行 caddy reload --force。`"
      confirm-text="确认回滚并重载"
      :loading="rollingBack"
      @confirm="confirmRollback"
      @cancel="rollbackConfirmOpen = false"
    />

    <!-- Delete Host Confirmation -->
    <ConfirmDialog
      :open="deleteConfirmOpen"
      title="删除主机"
      :message="`确定要删除主机「${selectedHost?.name || ''}」吗？`"
      confirm-text="确认删除"
      danger
      :loading="deleteLoading"
      @confirm="confirmDeleteHost"
      @cancel="deleteConfirmOpen = false"
    />
  </div>
</template>
