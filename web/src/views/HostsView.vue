<script setup lang="ts">
import { computed, defineAsyncComponent, onMounted, onUnmounted, reactive, ref, watch } from 'vue'
import { onBeforeRouteLeave, useRoute, useRouter } from 'vue-router'
import {
  AlertTriangle,
  CheckCircle2,
  ChevronDown,
  ChevronUp,
  Container,
  Copy,
  Edit3,
  FileCode2,
  FileText,
  History,
  KeyRound,
  Loader2,
  Plus,
  RefreshCw,
  RotateCcw,
  Save,
  Search,
  Send,
  Server,
  ShieldAlert,
  Sparkles,
  Terminal,
  Trash2,
  Upload,
  Wand2,
  WrapText,
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
import { listCertificates } from '@/api/certificates'
import { ApiError } from '@/api/client'
import { createCertificateDeployment, listDeploymentLogs, pushDeployment } from '@/api/deployments'
import {
  createHost,
  deleteHost,
  discoverHostCaddy,
  listHostDeployments,
  listHosts,
  probeHost,
  resetHostKey,
  testHostConnection,
  updateHost,
} from '@/api/hosts'
import ConfirmDialog from '@/components/ui/ConfirmDialog.vue'
import LineDiffViewer from '@/components/ui/LineDiffViewer.vue'
import ModalDialog from '@/components/ui/ModalDialog.vue'
import StatusBadge from '@/components/ui/StatusBadge.vue'
import { showToast } from '@/stores/toast'
import { certSubdirName, copyToClipboard, formatDateTime, truncateFingerprint } from '@/utils/format'
import type {
  CaddyConflictDetails,
  CaddyContainerInfo,
  CaddyDiffResponse,
  CaddySnapshotDTO,
  CaddyValidateErrorDetails,
  CertificateDTO,
  DeployLog,
  DeploymentDTO,
  DeployTemplate,
  DetectedCaddyConfig,
  DetectedContainer,
  DiscoverCaddyResponse,
  HostDTO,
  HostKeyPolicy,
  HostTestResult,
} from '@/types/api'

const CaddyEditor = defineAsyncComponent(() => import('@/components/ui/CaddyEditor.vue'))

const route = useRoute()
const router = useRouter()
const isMac = typeof navigator !== 'undefined' && /Mac|iPhone|iPad|iPod/i.test(navigator.platform || navigator.userAgent)
const saveShortcutLabel = isMac ? '⌘S' : 'Ctrl+S'

// ============================================================================
// Hosts List & Selection
// ============================================================================
const hosts = ref<HostDTO[]>([])
const hostsLoading = ref(false)
const selectedHostId = ref<number | null>(null)
const initialTab = route.query.tab === 'deployments' || route.query.tab === 'caddy' ? route.query.tab : 'info'
const activeTab = ref<'info' | 'deployments' | 'caddy'>(initialTab)

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

const pendingSwitchHost = ref<HostDTO | null>(null)
const dirtySwitchConfirmOpen = ref(false)

function selectHost(host: HostDTO) {
  if (host.id === selectedHostId.value) return
  if (isCaddyDirty.value) {
    pendingSwitchHost.value = host
    dirtySwitchConfirmOpen.value = true
    return
  }
  selectedHostId.value = host.id
}

function confirmSwitchHost() {
  dirtySwitchConfirmOpen.value = false
  if (pendingSwitchHost.value) {
    caddySavedContent.value = caddyContent.value
    selectedHostId.value = pendingSwitchHost.value.id
    pendingSwitchHost.value = null
  }
}

// ============================================================================
// Create / Edit Host Modal
// ============================================================================
const hostModalOpen = ref(false)
const editingHost = ref<HostDTO | null>(null)
const hostSaving = ref(false)
const hostAdvancedOpen = ref(false)
const modalProbing = ref(false)
const modalProbeResult = ref<HostTestResult | null>(null)

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
  hostAdvancedOpen.value = false
  modalProbeResult.value = null
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
  hostAdvancedOpen.value = false
  modalProbeResult.value = null
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

function handleSSHKeyFileSelect(event: Event) {
  const input = event.target as HTMLInputElement
  const file = input.files?.[0]
  if (!file) return
  const reader = new FileReader()
  reader.onload = () => {
    if (typeof reader.result === 'string') {
      hostForm.ssh_private_key = reader.result
      showToast('info', `已读取私钥文件 ${file.name}`)
    }
  }
  reader.readAsText(file)
  input.value = ''
}

function applyDetectedCaddyToForm(cfg: DetectedCaddyConfig) {
  if (cfg.container_name) hostForm.caddy_container = cfg.container_name
  if (cfg.host_caddyfile) hostForm.caddy_host_caddyfile = cfg.host_caddyfile
  if (cfg.container_caddyfile) hostForm.caddy_container_caddyfile = cfg.container_caddyfile
  if (cfg.host_cert_dir) hostForm.caddy_host_cert_dir = cfg.host_cert_dir
  if (cfg.container_cert_dir) hostForm.caddy_container_cert_dir = cfg.container_cert_dir
  hostAdvancedOpen.value = true
  showToast('success', `已回填容器「${cfg.container_name}」的挂载路径`)
}

async function handleProbeInModal(targetContainer?: string) {
  if (!editingHost.value?.is_local && !hostForm.host.trim()) {
    showToast('warning', '请先填写主机 IP 或域名')
    return
  }
  modalProbing.value = true
  modalProbeResult.value = null
  try {
    const res = await probeHost({
      host_id: editingHost.value?.id,
      name: hostForm.name.trim() || 'probe',
      mode: editingHost.value?.is_local ? 'local' : 'ssh',
      host: hostForm.host.trim(),
      port: Number(hostForm.port) || 22,
      username: hostForm.username.trim() || 'root',
      auth_type: hostForm.auth_type,
      ssh_private_key: hostForm.auth_type === 'key' ? hostForm.ssh_private_key.trim() || undefined : undefined,
      ssh_passphrase: hostForm.auth_type === 'key' ? hostForm.ssh_passphrase || undefined : undefined,
      ssh_password: hostForm.auth_type === 'password' ? hostForm.ssh_password || undefined : undefined,
      host_key_policy: hostForm.host_key_policy,
      caddy_enabled: hostForm.caddy_enabled,
      caddy_container: targetContainer || hostForm.caddy_container.trim() || 'caddy',
      caddy_host_caddyfile: hostForm.caddy_host_caddyfile.trim(),
      caddy_container_caddyfile: hostForm.caddy_container_caddyfile.trim(),
      caddy_host_cert_dir: hostForm.caddy_host_cert_dir.trim(),
      caddy_container_cert_dir: hostForm.caddy_container_cert_dir.trim(),
      target_container: targetContainer,
    })
    modalProbeResult.value = res
    if (res.ssh_ok && (!hostForm.caddy_enabled || (res.docker_ok && res.caddy_running))) {
      showToast('success', '连接与 Caddy 环境探测通过')
    } else if (res.ssh_ok) {
      showToast('warning', 'SSH 已连通，Caddy 环境存在待处理项，请查看下方提示')
    } else {
      showToast('error', 'SSH 连接失败，请检查地址与认证信息')
    }
  } catch (err) {
    showToast('error', err instanceof Error ? err.message : '探测失败')
  } finally {
    modalProbing.value = false
  }
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
// Tab 1: SSH Test, Caddy Discovery & Diagnostics, Reset Fingerprint & Delete
// ============================================================================
const testingConn = ref(false)
const testResult = ref<HostTestResult | null>(null)
const resettingFP = ref(false)
const discovering = ref(false)
const discoverResult = ref<DiscoverCaddyResponse | null>(null)
const applyingConfig = ref(false)
const disablingCaddy = ref(false)

async function handleTestConnection() {
  if (!selectedHost.value) return
  testingConn.value = true
  testResult.value = null
  discoverResult.value = null
  try {
    const res = await testHostConnection(selectedHost.value.id)
    testResult.value = res
    const caddyRequired = selectedHost.value.caddy_enabled
    if (res.ssh_ok && (!caddyRequired || (res.docker_ok && res.caddy_running))) {
      showToast('success', caddyRequired ? '主机连接与 Caddy 检测通过' : '主机 SSH 连接检测通过')
    } else {
      showToast('warning', res.message || '连接检测存在异常，请查看排查指引')
    }
    await loadHosts()
  } catch (err) {
    showToast('error', err instanceof Error ? err.message : '连接测试失败')
  } finally {
    testingConn.value = false
  }
}

async function handleDiscoverCaddy(containerName?: string) {
  if (!selectedHost.value) return
  discovering.value = true
  try {
    const res = await discoverHostCaddy(selectedHost.value.id, containerName)
    discoverResult.value = res
    if (res.detected_caddy_config) {
      showToast('success', `已探测到容器「${res.detected_caddy_config.container_name}」的挂载路径`)
    } else if (res.detected_containers.length > 0) {
      showToast('info', `发现 ${res.detected_containers.length} 个容器，请选择目标容器`)
    } else {
      showToast('warning', res.message || '未检测到运行中的 Caddy 容器')
    }
  } catch (err) {
    showToast('error', err instanceof Error ? err.message : '自动探测失败')
  } finally {
    discovering.value = false
  }
}

async function applyDiscoveredConfig(cfg: DetectedCaddyConfig) {
  if (!selectedHost.value) return
  applyingConfig.value = true
  try {
    await updateHost(selectedHost.value.id, {
      caddy_enabled: true,
      caddy_container: cfg.container_name || selectedHost.value.caddy_container,
      caddy_host_caddyfile: cfg.host_caddyfile || selectedHost.value.caddy_host_caddyfile,
      caddy_container_caddyfile: cfg.container_caddyfile || selectedHost.value.caddy_container_caddyfile,
      caddy_host_cert_dir: cfg.host_cert_dir || selectedHost.value.caddy_host_cert_dir,
      caddy_container_cert_dir: cfg.container_cert_dir || selectedHost.value.caddy_container_cert_dir,
    })
    showToast('success', `已自动保存「${cfg.container_name}」路径配置`)
    await loadHosts()
    await handleTestConnection()
  } catch (err) {
    showToast('error', err instanceof Error ? err.message : '应用探测配置失败')
  } finally {
    applyingConfig.value = false
  }
}

async function handleDisableCaddyForHost() {
  if (!selectedHost.value) return
  disablingCaddy.value = true
  try {
    await updateHost(selectedHost.value.id, { caddy_enabled: false })
    testResult.value = null
    discoverResult.value = null
    caddyLoadError.value = ''
    showToast('success', '已关闭该主机的 Caddy 管理工作台，可继续仅推送证书文件')
    await loadHosts()
  } catch (err) {
    showToast('error', err instanceof Error ? err.message : '操作失败')
  } finally {
    disablingCaddy.value = false
  }
}

interface DiagnosticGuide {
  title: string
  summary: string
  steps: string[]
  commands: { label: string; code: string }[]
}

function buildCaddyComposeSnippet(host: HostDTO): string {
  const name = host.caddy_container || 'caddy'
  const hostConfDir = parentDir(host.caddy_host_caddyfile || '/home/caddy/conf/Caddyfile')
  const containerConfDir = parentDir(host.caddy_container_caddyfile || '/etc/caddy/Caddyfile')
  const hostCertDir = host.caddy_host_cert_dir || '/home/caddy/certs'
  const containerCertDir = host.caddy_container_cert_dir || '/certs'
  return [
    'services:',
    '  caddy:',
    '    image: caddy:2-alpine',
    `    container_name: ${name}`,
    '    restart: unless-stopped',
    '    ports:',
    '      - "80:80"',
    '      - "443:443"',
    '    volumes:',
    `      - ${hostConfDir}:${containerConfDir}`,
    `      - ${hostCertDir}:${containerCertDir}`,
    '      - ./caddy_data:/data',
    '      - ./caddy_config:/config',
  ].join('\n')
}

function inferCaddyIssueCode(host: HostDTO): string {
  if (testResult.value?.caddy_issue_code) return testResult.value.caddy_issue_code
  if (testResult.value?.caddyfile_exists === false) return 'caddyfile_missing'
  if (caddyLoadError.value) {
    const low = caddyLoadError.value.toLowerCase()
    if (low.includes('no such file') || low.includes('does not exist') || low.includes('not exist') || low.includes('not found')) {
      return 'caddyfile_missing'
    }
  }
  const msg = (host.last_check_msg || '').toLowerCase()
  if (!msg || host.caddy_status === 'running') return ''
  if (msg.includes('permission denied') || msg.includes('docker.sock')) return 'docker_sock_permission'
  if (msg.includes('docker unavailable')) return 'docker_unavailable'
  if (msg.includes('is restarting')) return 'container_restarting'
  if (msg.includes('is stopped')) return 'container_stopped'
  if (msg.includes('inspect failed') || msg.includes('no such object')) return 'container_not_found'
  return ''
}

function getDiagnosticGuide(issueCode: string, host: HostDTO): DiagnosticGuide | null {
  const container = host.caddy_container || 'caddy'
  const hostCF = host.caddy_host_caddyfile || '/opt/caddy/Caddyfile'
  const hostConfDir = parentDir(hostCF)
  const hostCertDir = host.caddy_host_cert_dir || '/opt/caddy/certs'

  switch (issueCode) {
    case 'docker_sock_permission':
      return {
        title: '无法访问 Docker Socket（未挂载或无权限）',
        summary: host.is_local
          ? '内置 Local 模式需要 ssl-center 容器自身挂载宿主机的 /var/run/docker.sock，才能检测并热重载同机 Caddy 容器。'
          : '远程主机当前登录用户没有访问 /var/run/docker.sock 的权限，或 Docker 服务尚未启动。',
        steps: host.is_local
          ? [
              '在宿主机 ssl-center 的 docker-compose.yml 中挂载 /var/run/docker.sock 与 Caddy 目录',
              '执行 docker compose up -d 重建 ssl-center 容器后重试',
              '若不想挂载 docker.sock，也可以新建 SSH 主机来管理本机',
            ]
          : [
              `将 SSH 用户 ${host.username} 加入 docker 用户组，或改用 root 连接`,
              '确认宿主机 Docker 守护进程已启动（systemctl status docker）',
            ],
        commands: [
          host.is_local
            ? { label: 'ssl-center docker-compose.yml volumes 示例', code: localCaddyMountSnippet.value }
            : { label: '授予 Docker 权限并启动', code: `sudo usermod -aG docker ${host.username} && sudo systemctl enable --now docker` },
        ],
      }
    case 'docker_unavailable':
      return {
        title: '主机尚未安装或启动 Docker',
        summary: '当前主机的 Caddy Docker 管理依赖 Docker 环境，但检测命令未发现运行中的 Docker 守护进程。',
        steps: [
          '如果这台主机只用来接收证书文件（不通过 Docker 运行 Caddy），可点击下方「暂不管理 Caddy」',
          '若需要在该主机部署 Caddy Docker，请先安装并启动 Docker',
        ],
        commands: [
          { label: '安装并启动 Docker (Linux)', code: 'curl -fsSL https://get.docker.com | sh && sudo systemctl enable --now docker' },
        ],
      }
    case 'container_not_found':
      return {
        title: `未找到名为「${container}」的 Caddy 容器`,
        summary: 'Docker 正常运行，但未找到配置中指定的容器名称。可能是容器名不同，或尚未部署 Caddy。',
        steps: [
          '点击「自动探测容器」，若宿主机已有其他名称的 Caddy 容器可直接一键回填路径',
          '若尚未部署 Caddy，可复制下方标准 docker-compose.yml（推荐使用目录挂载，支持原子替换与零中断重载）',
        ],
        commands: [
          {
            label: '初始化目录并部署 Caddy 容器',
            code: `mkdir -p ${hostConfDir} ${hostCertDir}\ntouch ${hostCF}\ncat <<'EOF' > docker-compose.yml\n${buildCaddyComposeSnippet(host)}\nEOF\ndocker compose up -d`,
          },
        ],
      }
    case 'container_stopped':
      return {
        title: `Caddy 容器「${container}」当前已停止`,
        summary: '容器存在但未处于运行状态，无法执行预校验或热重载。',
        steps: ['在宿主机执行启动命令恢复容器，若启动后立即退出请检查容器日志。'],
        commands: [
          { label: '启动容器并查看日志', code: `docker start ${container} && docker logs --tail 50 ${container}` },
        ],
      }
    case 'container_restarting':
      return {
        title: `Caddy 容器「${container}」正在不断重启`,
        summary: '通常是 Caddyfile 语法错误或证书路径在容器内不存在导致容器启动失败。',
        steps: [
          '打开右上角「容器状态与日志」查看具体启动报错',
          '核对 Caddyfile 中引用的 tls 路径是否存在于容器挂载目录内，修正后通过编辑器重新保存',
        ],
        commands: [
          { label: '查看最近重启日志', code: `docker logs --tail 80 ${container}` },
        ],
      }
    case 'caddyfile_missing':
      return {
        title: `未找到 Caddyfile 文件：${hostCF}`,
        summary: host.is_local
          ? 'Local 模式下，ssl-center 容器内部直接按宿主机相同路径读取 Caddyfile。请确认宿主机文件已创建，且已将所在目录挂载到 ssl-center 容器内。'
          : '目标主机上尚不存在该路径的 Caddyfile 文件，或配置的宿主机路径与实际挂载目录不一致。',
        steps: host.is_local
          ? [
              `在宿主机确认文件存在：ls -l ${hostCF}`,
              '确保 ssl-center 的 docker-compose.yml 已按相同路径挂载 Caddy 配置目录与证书目录',
              '或点击「自动探测容器」自动识别真实挂载路径',
            ]
          : [
              '点击「自动探测容器」确认宿主机真实 Caddyfile 挂载路径',
              '如果确系新部署空文件，可点击「填入最小 Caddyfile 模板」直接在线初始化并保存',
            ],
        commands: host.is_local
          ? [{ label: 'ssl-center docker-compose.yml volumes 示例', code: localCaddyMountSnippet.value }]
          : [{ label: '在宿主机创建空 Caddyfile 目录与文件', code: `mkdir -p ${hostConfDir} ${hostCertDir} && touch ${hostCF}` }],
      }
    case 'invalid_container_name':
      return {
        title: 'Caddy 容器名称格式不合法',
        summary: '容器名称仅允许字母、数字、下划线（_）、点（.）与连字符（-）。',
        steps: ['点击右上角「编辑配置」修改容器名称后重新检测。'],
        commands: [],
      }
    default:
      return null
  }
}

const activeDiagnosticGuide = computed(() => {
  if (!selectedHost.value || !selectedHost.value.caddy_enabled) return null
  const code = inferCaddyIssueCode(selectedHost.value)
  if (!code) return null
  return getDiagnosticGuide(code, selectedHost.value)
})

const detectedContainersToShow = computed<DetectedContainer[]>(() => {
  return discoverResult.value?.detected_containers || testResult.value?.detected_containers || []
})

const detectedConfigToShow = computed<DetectedCaddyConfig | null>(() => {
  return discoverResult.value?.detected_caddy_config || testResult.value?.detected_caddy_config || null
})

async function copyCommand(label: string, code: string) {
  const ok = await copyToClipboard(code)
  showToast(ok ? 'success' : 'error', ok ? `已复制「${label}」` : '复制失败')
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
// Tab 2: Deployed Certificates on This Host + Quick Bind Cert
// ============================================================================
const hostDeployments = ref<DeploymentDTO[]>([])
const loadedDeploymentsHostId = ref<number | null>(null)
const deploymentsLoading = ref(false)
const pushingId = ref<number | null>(null)
const logsModalOpen = ref(false)
const logsTargetName = ref('')
const logsTargetTlsEnabled = ref(true)
const deployLogs = ref<DeployLog[]>([])
const deployLogsLoading = ref(false)

const bindCertModalOpen = ref(false)
const allCerts = ref<CertificateDTO[]>([])
const allCertsLoading = ref(false)
const bindSaving = ref(false)
const bindForm = reactive({
  certificate_id: 0,
  template: 'caddy_docker' as DeployTemplate,
  name: '',
})

async function loadHostDeployments(hostId: number, force = false) {
  if (!force && loadedDeploymentsHostId.value === hostId) return
  deploymentsLoading.value = true
  try {
    hostDeployments.value = await listHostDeployments(hostId)
    loadedDeploymentsHostId.value = hostId
  } catch (err) {
    showToast('error', err instanceof Error ? err.message : '加载已部署证书失败')
  } finally {
    deploymentsLoading.value = false
  }
}

async function openBindCertModal() {
  if (!selectedHost.value) return
  bindForm.template = selectedHost.value.is_local && !selectedHost.value.caddy_enabled ? 'local_dir' : 'caddy_docker'
  bindForm.name = ''
  bindCertModalOpen.value = true
  allCertsLoading.value = true
  try {
    allCerts.value = await listCertificates()
    if (allCerts.value.length > 0) {
      bindForm.certificate_id = allCerts.value[0].id
      bindForm.name = `${selectedHost.value.name} Caddy`
    } else {
      bindForm.certificate_id = 0
    }
  } catch (err) {
    showToast('error', err instanceof Error ? err.message : '加载证书列表失败')
  } finally {
    allCertsLoading.value = false
  }
}

async function submitBindCert() {
  if (!selectedHost.value || !bindForm.certificate_id) {
    showToast('warning', '请选择要绑定的证书')
    return
  }
  const cert = allCerts.value.find((c) => c.id === bindForm.certificate_id)
  if (!cert) return

  const h = selectedHost.value
  const baseCertDir = (h.caddy_host_cert_dir || '/opt/caddy/certs').replace(/\/+$/, '')
  const subDir = `${baseCertDir}/${certSubdirName(cert.domain, cert.id)}`
  const container = h.caddy_container || 'caddy'
  const caddyfile = h.caddy_container_caddyfile || '/etc/caddy/Caddyfile'

  bindSaving.value = true
  try {
    await createCertificateDeployment(cert.id, {
      host_id: h.id,
      name: bindForm.name.trim() || `${h.name} Caddy`,
      template: bindForm.template,
      enabled: true,
      fullchain_path: `${subDir}/fullchain.pem`,
      privkey_path: `${subDir}/privkey.pem`,
      issuer_path: `${subDir}/issuer.pem`,
      cert_file_mode: '0644',
      key_file_mode: '0600',
      reload_mode: bindForm.template === 'caddy_docker' ? 'docker_exec' : 'none',
      reload_command: bindForm.template === 'caddy_docker' ? `docker exec '${container}' caddy reload --config '${caddyfile}' --force` : '',
      reload_webhook_url: '',
      tls_verify_enabled: true,
      tls_verify_host: !h.is_local ? h.host : '',
      tls_verify_port: 443,
      tls_verify_sni: cert.domain.startsWith('*.') ? cert.domain.slice(2) : cert.domain,
    })
    bindCertModalOpen.value = false
    showToast('success', `已将证书「${cert.domain}」绑定到当前主机`)
    await Promise.all([loadHostDeployments(h.id, true), loadHosts(true)])
  } catch (err) {
    showToast('error', err instanceof Error ? err.message : '绑定失败')
  } finally {
    bindSaving.value = false
  }
}

async function handleQuickPush(d: DeploymentDTO) {
  pushingId.value = d.id
  try {
    const log = await pushDeployment(d.id)
    if (log.status === 'success') {
      if (d.tls_verify_enabled && !log.tls_verified && log.error_message) {
        showToast('warning', `「${d.name}」证书已写入，首次 TLS 指纹尚未生效；请更新 Caddyfile 后再次推送验证`)
      } else {
        showToast('success', `「${d.name}」推送成功`)
      }
    } else {
      showToast('error', `「${d.name}」推送失败: ${log.error_message || '请查看日志'}`)
    }
    if (selectedHost.value) {
      await loadHostDeployments(selectedHost.value.id, true)
    }
  } catch (err) {
    showToast('error', err instanceof Error ? err.message : '推送失败')
  } finally {
    pushingId.value = null
  }
}

async function openDeployLogs(d: DeploymentDTO) {
  logsTargetName.value = d.name
  logsTargetTlsEnabled.value = d.tls_verify_enabled
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
const caddyLoadedOnce = ref(false)
const caddyContent = ref('')
const caddySavedContent = ref('')
const expectedSHA256 = ref('')
const caddyMountType = ref('')
const caddyHostPath = ref('')
const caddySummary = ref('')
const caddyLineWrap = ref(false)
const caddyErrorLine = ref<number | null>(null)
const caddyFeedback = ref<{ ok: boolean; title: string; output: string } | null>(null)
const caddyLoadError = ref('')

const isCaddyDirty = computed(() => caddyLoadedOnce.value && caddyContent.value !== caddySavedContent.value)

const siteGenForm = reactive({
  deploymentId: 0,
  domain: '',
  upstream: '127.0.0.1:8080',
  enableEncode: true,
})

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
const containerLogSearch = ref('')
const containerLogPretty = ref(false)

const filteredContainerLogs = computed(() => {
  const raw = containerInfo.value?.logs || ''
  if (!raw) return '暂无日志输出'
  const lines = raw.split('\n')
  const q = containerLogSearch.value.trim().toLowerCase()
  const matched = q ? lines.filter((l) => l.toLowerCase().includes(q)) : lines
  if (!containerLogPretty.value) {
    return matched.length > 0 ? matched.join('\n') : '无匹配日志行'
  }
  const formatted = matched.map((line) => {
    const trimmed = line.trim()
    if (trimmed.startsWith('{') && trimmed.endsWith('}')) {
      try {
        return JSON.stringify(JSON.parse(trimmed), null, 2)
      } catch {
        return line
      }
    }
    return line
  })
  return formatted.length > 0 ? formatted.join('\n') : '无匹配日志行'
})

async function loadCaddyfile() {
  if (!selectedHost.value || !selectedHost.value.caddy_enabled) return
  caddyLoading.value = true
  caddyLoadError.value = ''
  caddyErrorLine.value = null
  caddyFeedback.value = null
  try {
    const res = await getCaddyfile(selectedHost.value.id)
    caddyContent.value = res.content
    caddySavedContent.value = res.content
    caddyLoadedOnce.value = true
    expectedSHA256.value = res.sha256
    caddyMountType.value = res.mount_type
    caddyHostPath.value = res.host_caddyfile_path
  } catch (err) {
    caddyLoadError.value = err instanceof Error ? err.message : '拉取远程 Caddyfile 失败'
  } finally {
    caddyLoading.value = false
  }
}

function initStarterCaddyfile() {
  const firstDep = hostDeployments.value[0]
  const sampleDomain = firstDep?.cert_domain ? (firstDep.cert_domain.startsWith('*.') ? firstDep.cert_domain.slice(2) : firstDep.cert_domain) : 'example.com'
  const tlsLine = firstDep ? `\t${buildTlsSnippet(firstDep)}\n` : ''
  caddyContent.value = `# SSL Center 初始化模板\n${sampleDomain} {\n${tlsLine}\treverse_proxy 127.0.0.1:8080\n}\n`
  caddySavedContent.value = ''
  caddyLoadedOnce.value = true
  caddyLoadError.value = ''
  expectedSHA256.value = ''
  showToast('info', '已填入最小 Caddyfile 模板，修改后点击「保存并重载」即可创建线上配置')
}

function parentDir(filePath: string): string {
  const normalized = filePath.trim().replace(/\/+$/, '')
  if (!normalized) return '/opt/caddy'
  const idx = normalized.lastIndexOf('/')
  if (idx === -1) return '/opt/caddy'
  if (idx === 0) return '/'
  return normalized.slice(0, idx)
}

const localCaddyMountSnippet = computed(() => {
  const caddyDir = parentDir(selectedHost.value?.caddy_host_caddyfile || '/opt/caddy/Caddyfile')
  const certDir =
    (selectedHost.value?.caddy_host_cert_dir || '/opt/caddy/certs').trim().replace(/\/+$/, '') ||
    '/opt/caddy/certs'
  const lines = [
    'volumes:',
    '  - ./data:/data',
    '  - /var/run/docker.sock:/var/run/docker.sock',
    `  - ${caddyDir}:${caddyDir}`,
  ]
  if (certDir !== caddyDir) {
    lines.push(`  - ${certDir}:${certDir}`)
  }
  return lines.join('\n')
})

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

function insertReverseProxyBlock() {
  const domain = siteGenForm.domain.trim()
  const upstream = siteGenForm.upstream.trim()
  if (!domain || !upstream) {
    showToast('warning', '请填写站点域名与后端反代地址')
    return
  }
  const dep = hostDeployments.value.find((d) => d.id === siteGenForm.deploymentId)
  const tlsLine = dep ? `\t${buildTlsSnippet(dep)}\n` : ''
  const encodeLine = siteGenForm.enableEncode ? '\tencode zstd gzip\n' : ''
  const block = `\n${domain} {\n${tlsLine}${encodeLine}\treverse_proxy ${upstream}\n}`
  caddyEditorRef.value?.insertSnippet(block)
  showToast('success', `已插入 ${domain} 反向代理站点块`)
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
    caddySavedContent.value = caddyContent.value
    caddyLoadedOnce.value = true
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
  caddySavedContent.value = conflictDetails.value.remote_content
  caddyLoadedOnce.value = true
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
// Reactive Sync on Host or Tab Change + Dirty Draft Guard
// ============================================================================
watch(selectedHostId, (id) => {
  testResult.value = null
  discoverResult.value = null
  caddyContent.value = ''
  caddySavedContent.value = ''
  caddyLoadedOnce.value = false
  expectedSHA256.value = ''
  caddyFeedback.value = null
  caddyLoadError.value = ''
  caddyErrorLine.value = null
  loadedDeploymentsHostId.value = null
  if (!id) return
  void loadHostDeployments(id, true)
  if (activeTab.value === 'caddy') {
    void loadCaddyfile()
  }
})

watch(hostDeployments, (deps) => {
  if (deps.length > 0) {
    const first = deps[0]
    if (!deps.some((d) => d.id === siteGenForm.deploymentId)) {
      siteGenForm.deploymentId = first.id
    }
    if (!siteGenForm.domain && first.cert_domain) {
      siteGenForm.domain = first.cert_domain.startsWith('*.')
        ? `app.${first.cert_domain.slice(2)}`
        : first.cert_domain
    }
  } else {
    siteGenForm.deploymentId = 0
  }
})

watch(activeTab, (tab) => {
  if (!selectedHost.value) return
  if (tab === 'deployments') {
    void loadHostDeployments(selectedHost.value.id)
  } else if (tab === 'caddy') {
    void loadHostDeployments(selectedHost.value.id)
    if (!caddyLoadedOnce.value && !caddyLoading.value) {
      void loadCaddyfile()
    }
  }
})

function handleBeforeUnload(e: BeforeUnloadEvent) {
  if (isCaddyDirty.value) {
    e.preventDefault()
    e.returnValue = ''
  }
}

onBeforeRouteLeave((_to, _from, next) => {
  if (isCaddyDirty.value && !window.confirm('Caddyfile 编辑器存在未保存的改动，确定离开吗？')) {
    next(false)
    return
  }
  next()
})

onMounted(() => {
  window.addEventListener('beforeunload', handleBeforeUnload)
  void loadHosts()
})

onUnmounted(() => {
  window.removeEventListener('beforeunload', handleBeforeUnload)
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
      <div class="min-w-0 space-y-3 lg:col-span-4 xl:col-span-3">
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

          <div class="mt-2 truncate font-mono text-xs text-slate-500">
            {{ h.is_local ? 'Local Host (无 SSH)' : `${h.username}@${h.host}:${h.port}` }}
          </div>

          <div class="mt-3 flex flex-wrap items-center justify-between gap-2 text-[11px]">
            <div class="flex flex-wrap items-center gap-1.5">
              <span
                class="inline-flex items-center gap-1 rounded-full px-2 py-0.5 font-medium ring-1 ring-inset"
                :class="
                  h.last_check_ok === true
                    ? 'bg-emerald-50 text-emerald-700 ring-emerald-600/20'
                    : h.last_check_ok === false
                      ? 'bg-rose-50 text-rose-700 ring-rose-600/20'
                      : 'bg-slate-100 text-slate-600 ring-slate-500/20'
                "
              >
                <span
                  class="h-1.5 w-1.5 rounded-full"
                  :class="
                    h.last_check_ok === true
                      ? 'bg-emerald-500'
                      : h.last_check_ok === false
                        ? 'bg-rose-500'
                        : 'bg-slate-400'
                  "
                />
                {{ h.last_check_ok === true ? '在线' : h.last_check_ok === false ? '离线' : '未检测' }}
              </span>
              <StatusBadge v-if="h.caddy_enabled" :status="h.caddy_status || 'unknown'" />
              <span v-else class="rounded bg-slate-100 px-2 py-0.5 text-slate-500">未启用 Caddy</span>
            </div>
            <span class="text-slate-500 tabular-nums">{{ h.deployment_count }} 个部署</span>
          </div>
        </button>
      </div>

      <!-- Right Column: 3-Tab Host & Caddy Workbench -->
      <div class="min-w-0 lg:col-span-8 xl:col-span-9">
        <div
          v-if="!selectedHost"
          class="rounded-xl border border-dashed border-slate-300 bg-white p-12 text-center text-sm text-slate-500"
        >
          请从左侧选择一台主机查看详情与 Caddy 工作台
        </div>

        <div v-else class="overflow-hidden rounded-xl border border-slate-200 bg-white shadow-sm">
          <!-- Workbench Header + Tabs -->
          <div class="border-b border-slate-200 px-4 pt-5 sm:px-6">
            <div class="flex flex-wrap items-center justify-between gap-3">
              <div class="min-w-0 flex-1">
                <div class="flex flex-wrap items-center gap-2">
                  <h2 class="truncate text-lg font-bold text-slate-900">{{ selectedHost.name }}</h2>
                  <span
                    v-if="selectedHost.is_local"
                    class="shrink-0 rounded-full bg-indigo-50 px-2.5 py-0.5 text-xs font-semibold text-indigo-700"
                  >
                    内置本机 (不可删除)
                  </span>
                </div>
                <p class="mt-0.5 break-all font-mono text-xs text-slate-500">
                  {{
                    selectedHost.is_local
                      ? `容器: ${selectedHost.caddy_container || '—'} · 证书目录: ${selectedHost.caddy_host_cert_dir || '—'}`
                      : `${selectedHost.username}@${selectedHost.host}:${selectedHost.port} · 策略: ${selectedHost.host_key_policy}`
                  }}
                </p>
              </div>
              <div class="flex flex-wrap items-center gap-2">
                <template v-if="selectedHost.caddy_enabled">
                  <button
                    type="button"
                    :disabled="selectedHost.caddy_status !== 'running'"
                    :title="selectedHost.caddy_status !== 'running' ? 'Caddy 容器未运行，请先检测或部署容器' : '查看容器状态与日志'"
                    class="inline-flex items-center gap-1.5 rounded-lg border border-slate-200 px-3 py-1.5 text-xs font-medium text-slate-700 hover:bg-slate-50 disabled:cursor-not-allowed disabled:opacity-50"
                    @click="openContainerModal"
                  >
                    <Terminal class="h-3.5 w-3.5 text-slate-500" />
                    容器状态与日志
                  </button>
                  <button
                    type="button"
                    :disabled="reloading || selectedHost.caddy_status !== 'running'"
                    :title="selectedHost.caddy_status !== 'running' ? 'Caddy 容器未运行，无法重载' : '不修改 Caddyfile，直接执行容器热重载'"
                    class="inline-flex items-center gap-1.5 rounded-lg border border-slate-200 px-3 py-1.5 text-xs font-medium text-slate-700 hover:bg-slate-50 disabled:cursor-not-allowed disabled:opacity-50"
                    @click="handleReloadOnly"
                  >
                    <RotateCcw class="h-3.5 w-3.5 text-sky-600" :class="reloading ? 'animate-spin' : ''" />
                    仅重载 Caddy
                  </button>
                  <span class="mx-0.5 hidden h-4 w-px bg-slate-200 sm:inline-block" />
                </template>
                <button
                  type="button"
                  class="inline-flex items-center gap-1.5 rounded-lg border border-slate-200 px-3 py-1.5 text-xs font-medium text-slate-700 hover:bg-slate-50"
                  @click="openEditHost(selectedHost)"
                >
                  <Edit3 class="h-3.5 w-3.5" />
                  编辑配置
                </button>
              </div>
            </div>

            <div class="mt-4 flex gap-4 overflow-x-auto sm:gap-6">
              <button
                type="button"
                class="shrink-0 border-b-2 pb-3 text-xs font-semibold transition"
                :class="
                  activeTab === 'info'
                    ? 'border-indigo-600 text-indigo-600'
                    : 'border-transparent text-slate-500 hover:text-slate-800'
                "
                @click="activeTab = 'info'"
              >
                ① 主机信息与检测
              </button>
              <button
                type="button"
                class="shrink-0 border-b-2 pb-3 text-xs font-semibold transition"
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
                class="inline-flex shrink-0 items-center gap-1.5 border-b-2 pb-3 text-xs font-semibold transition"
                :class="
                  activeTab === 'caddy'
                    ? 'border-indigo-600 text-indigo-600'
                    : 'border-transparent text-slate-500 hover:text-slate-800'
                "
                @click="activeTab = 'caddy'"
              >
                <span>③ Caddyfile 编辑器</span>
                <span v-if="isCaddyDirty" class="rounded bg-amber-100 px-1.5 py-0.5 text-[10px] font-semibold text-amber-700">
                  未保存
                </span>
              </button>
            </div>
          </div>

          <!-- Tab 1: Host Info & SSH Test -->
          <div v-if="activeTab === 'info'" class="space-y-6 p-4 sm:p-6">
            <div class="flex flex-wrap items-center justify-between gap-3 rounded-xl border border-slate-200 bg-slate-50 p-4">
              <div class="min-w-0 flex-1">
                <div class="text-sm font-semibold text-slate-900">连通性与 Docker 环境检测</div>
                <div class="mt-0.5 break-words text-xs text-slate-500">
                  上次检测: {{ formatDateTime(selectedHost.last_check_at) }}
                  <span v-if="selectedHost.last_check_msg">· {{ selectedHost.last_check_msg }}</span>
                </div>
              </div>
              <div class="flex flex-wrap items-center gap-2">
                <button
                  v-if="selectedHost.caddy_enabled"
                  type="button"
                  :disabled="discovering"
                  class="inline-flex items-center gap-1.5 rounded-lg border border-slate-300 bg-white px-3 py-2 text-xs font-medium text-slate-700 hover:bg-slate-50 disabled:opacity-50"
                  @click="handleDiscoverCaddy()"
                >
                  <Search class="h-3.5 w-3.5 text-indigo-600" />
                  {{ discovering ? '探测中...' : '自动探测 Caddy' }}
                </button>
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
            </div>

            <!-- Live Test Result Box -->
            <div
              v-if="testResult"
              class="space-y-2 rounded-xl border p-4 text-xs"
              :class="
                testResult.ssh_ok && (!selectedHost.caddy_enabled || (testResult.docker_ok && testResult.caddy_running))
                  ? 'border-emerald-200 bg-emerald-50 text-emerald-900'
                  : 'border-amber-200 bg-amber-50 text-amber-900'
              "
            >
              <div class="flex flex-wrap items-center gap-3 font-semibold">
                <span>SSH/本机: {{ testResult.ssh_ok ? '正常' : '失败' }}</span>
                <template v-if="selectedHost.caddy_enabled">
                  <span>Docker: {{ testResult.docker_ok ? '可用' : '不可用' }}</span>
                  <span>Caddy 容器: {{ testResult.caddy_running ? '运行中' : '未运行' }}</span>
                  <span v-if="testResult.caddy_version" class="font-mono">({{ testResult.caddy_version }})</span>
                </template>
              </div>
              <div v-if="testResult.host_key_fingerprint" class="font-mono text-[11px] break-all">
                Host Key ({{ testResult.host_key_status }}): {{ testResult.host_key_fingerprint }}
              </div>
              <div>{{ testResult.message }}</div>
            </div>

            <!-- Caddy Diagnostic & Remediation Guidance Card -->
            <div
              v-if="activeDiagnosticGuide"
              class="space-y-3 rounded-xl border border-amber-200 bg-amber-50/80 p-4 text-xs text-amber-950"
            >
              <div class="flex flex-wrap items-start justify-between gap-2">
                <div class="flex items-start gap-2.5">
                  <AlertTriangle class="mt-0.5 h-4 w-4 shrink-0 text-amber-600" />
                  <div>
                    <div class="font-semibold text-amber-950">{{ activeDiagnosticGuide.title }}</div>
                    <p class="mt-0.5 leading-relaxed text-amber-900/90">{{ activeDiagnosticGuide.summary }}</p>
                  </div>
                </div>
                <button
                  type="button"
                  :disabled="disablingCaddy"
                  class="shrink-0 rounded-lg border border-amber-300 bg-white px-2.5 py-1 text-[11px] font-medium text-amber-900 hover:bg-amber-100 disabled:opacity-50"
                  @click="handleDisableCaddyForHost"
                >
                  {{ disablingCaddy ? '处理中...' : '暂不管理 Caddy（仅推送证书）' }}
                </button>
              </div>

              <ul v-if="activeDiagnosticGuide.steps.length > 0" class="list-disc space-y-1 pl-5 text-amber-900">
                <li v-for="(step, idx) in activeDiagnosticGuide.steps" :key="idx">{{ step }}</li>
              </ul>

              <div v-for="cmd in activeDiagnosticGuide.commands" :key="cmd.label" class="space-y-1">
                <div class="flex items-center justify-between text-[11px] font-medium text-amber-900">
                  <span>{{ cmd.label }}</span>
                  <button
                    type="button"
                    class="inline-flex items-center gap-1 rounded bg-white px-2 py-0.5 text-[11px] font-semibold text-indigo-700 ring-1 ring-amber-300 hover:bg-indigo-50"
                    @click="copyCommand(cmd.label, cmd.code)"
                  >
                    <Copy class="h-3 w-3" />
                    复制命令
                  </button>
                </div>
                <pre class="overflow-x-auto rounded-lg bg-slate-900 p-2.5 font-mono text-[11px] text-slate-100">{{ cmd.code }}</pre>
              </div>
            </div>

            <!-- Auto-Discovered Containers & Caddy Mounts -->
            <div
              v-if="detectedContainersToShow.length > 0 || detectedConfigToShow"
              class="space-y-3 rounded-xl border border-indigo-200 bg-indigo-50/50 p-4 text-xs"
            >
              <div class="flex flex-wrap items-center justify-between gap-2">
                <div class="font-semibold text-indigo-950">探测到的宿主机 Docker 容器与 Caddy 路径</div>
                <button
                  v-if="detectedConfigToShow"
                  type="button"
                  :disabled="applyingConfig"
                  class="inline-flex items-center gap-1.5 rounded-lg bg-indigo-600 px-3 py-1.5 text-xs font-semibold text-white hover:bg-indigo-700 disabled:opacity-50"
                  @click="applyDiscoveredConfig(detectedConfigToShow)"
                >
                  <CheckCircle2 class="h-3.5 w-3.5" />
                  {{ applyingConfig ? '应用中...' : `一键回填「${detectedConfigToShow.container_name}」路径并保存` }}
                </button>
              </div>

              <div v-if="detectedConfigToShow" class="grid gap-2 rounded-lg border border-indigo-200 bg-white p-3 font-mono text-[11px] text-slate-700 sm:grid-cols-2">
                <div>容器名: {{ detectedConfigToShow.container_name }}</div>
                <div>挂载类型: {{ detectedConfigToShow.mount_type || '未知' }}</div>
                <div class="truncate" :title="detectedConfigToShow.host_caddyfile">
                  宿主机 Caddyfile: {{ detectedConfigToShow.host_caddyfile || '未检测到挂载' }}
                </div>
                <div class="truncate" :title="detectedConfigToShow.host_cert_dir">
                  宿主机证书目录: {{ detectedConfigToShow.host_cert_dir || '未检测到挂载' }}
                </div>
              </div>

              <div v-if="detectedContainersToShow.length > 0" class="flex flex-wrap gap-2">
                <button
                  v-for="c in detectedContainersToShow"
                  :key="c.name"
                  type="button"
                  :disabled="discovering"
                  class="inline-flex items-center gap-1.5 rounded-lg border bg-white px-2.5 py-1.5 text-xs transition hover:border-indigo-400"
                  :class="c.is_caddy ? 'border-indigo-300 text-indigo-800' : 'border-slate-200 text-slate-700'"
                  @click="handleDiscoverCaddy(c.name)"
                >
                  <span class="h-2 w-2 rounded-full" :class="c.running ? 'bg-emerald-500' : 'bg-slate-400'" />
                  <span class="font-mono font-semibold">{{ c.name }}</span>
                  <span class="text-[11px] text-slate-400">{{ c.image }}</span>
                  <span v-if="c.is_caddy" class="rounded bg-indigo-100 px-1.5 py-0.5 text-[10px] font-semibold text-indigo-700">Caddy</span>
                </button>
              </div>
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

            <!-- Danger Zone (hidden for protected Local host) -->
            <div
              v-if="!selectedHost.is_local"
              class="flex items-center justify-between rounded-xl border border-rose-100 bg-rose-50/40 p-4"
            >
              <div>
                <div class="text-xs font-semibold text-rose-900">删除主机</div>
                <div class="text-xs text-rose-700/80">
                  删除前需先移除该主机关联的所有证书部署目标
                </div>
              </div>
              <button
                type="button"
                class="inline-flex items-center gap-1.5 rounded-lg border border-rose-200 bg-white px-3 py-1.5 text-xs font-semibold text-rose-600 hover:bg-rose-50"
                @click="deleteConfirmOpen = true"
              >
                <Trash2 class="h-3.5 w-3.5" />
                删除主机
              </button>
            </div>
          </div>

          <!-- Tab 2: Deployed Certificates -->
          <div v-else-if="activeTab === 'deployments'" class="space-y-4 p-4 sm:p-6">
            <div class="flex flex-wrap items-center justify-between gap-2">
              <p class="text-xs text-slate-500">
                以下证书会在签发或续期成功后自动推送到此主机并执行重载校验
              </p>
              <button
                type="button"
                class="inline-flex items-center gap-1.5 rounded-lg bg-indigo-600 px-3 py-1.5 text-xs font-semibold text-white hover:bg-indigo-700"
                @click="openBindCertModal"
              >
                <Plus class="h-3.5 w-3.5" />
                绑定证书到此主机
              </button>
            </div>

            <div v-if="deploymentsLoading && hostDeployments.length === 0" class="py-10 text-center text-sm text-slate-500">
              加载该主机的部署记录...
            </div>
            <div
              v-else-if="hostDeployments.length === 0"
              class="rounded-xl border border-dashed border-slate-300 p-10 text-center text-xs text-slate-500"
            >
              暂无证书绑定到该主机，点击右上角「绑定证书到此主机」即可快速关联。
            </div>
            <div v-else class="space-y-3">
              <div
                v-for="d in hostDeployments"
                :key="d.id"
                class="rounded-xl border border-slate-200 p-4"
              >
                <div class="flex flex-wrap items-center justify-between gap-3">
                  <div class="min-w-0 flex-1">
                    <div class="flex flex-wrap items-center gap-2">
                      <span class="text-sm font-semibold text-slate-900">{{ d.cert_domain || `Cert #${d.certificate_id}` }}</span>
                      <span class="text-xs text-slate-500">({{ d.name }})</span>
                      <StatusBadge :status="d.last_status || 'pending'" />
                      <span
                        v-if="d.tls_verify_enabled && d.last_status === 'success' && !d.last_cert_fingerprint"
                        class="rounded-full bg-amber-50 px-2 py-0.5 text-[11px] font-medium text-amber-700 ring-1 ring-amber-200"
                      >
                        待 TLS 生效
                      </span>
                    </div>
                    <div class="mt-1 break-all font-mono text-[11px] text-slate-500">
                      {{ d.fullchain_path }}
                    </div>
                    <div class="mt-1 text-[11px] text-slate-400 tabular-nums">
                      最近推送: {{ formatDateTime(d.last_deployed_at) }}
                      <span v-if="d.last_cert_fingerprint">· FP: {{ truncateFingerprint(d.last_cert_fingerprint, 8) }}</span>
                    </div>
                    <div
                      v-if="d.last_error"
                      class="mt-1 break-words text-xs"
                      :class="d.last_status === 'success' ? 'text-amber-700' : 'text-rose-600'"
                    >
                      {{ d.last_error }}
                    </div>
                  </div>
                  <div class="flex flex-wrap items-center gap-2">
                    <button
                      v-if="d.tls_verify_enabled && d.last_status === 'success' && !d.last_cert_fingerprint && selectedHost.caddy_enabled"
                      type="button"
                      class="inline-flex items-center gap-1 rounded-lg border border-amber-200 bg-amber-50 px-2.5 py-1.5 text-xs font-medium text-amber-800 hover:bg-amber-100"
                      @click="activeTab = 'caddy'"
                    >
                      <FileCode2 class="h-3 w-3" />
                      配置 Caddyfile
                    </button>
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
                    <button
                      type="button"
                      class="inline-flex items-center gap-1 rounded-lg border border-slate-200 px-2.5 py-1.5 text-xs font-medium text-slate-700 hover:bg-slate-50"
                      @click="router.push({ path: '/certificates', query: { certId: String(d.certificate_id), tab: 'deployments' } })"
                    >
                      <Edit3 class="h-3 w-3 text-slate-500" />
                      部署配置
                    </button>
                  </div>
                </div>
              </div>
            </div>
          </div>

          <!-- Tab 3: Caddyfile Editor Workbench -->
          <div v-else class="p-4 sm:p-6">
            <div
              v-if="!selectedHost.caddy_enabled"
              class="rounded-xl border border-dashed border-slate-300 p-10 text-center text-sm text-slate-500"
            >
              该主机尚未启用「Caddy Docker 档案」，请点击右上角「编辑配置」开启后使用在线工作台。
            </div>

            <div v-else class="space-y-4">
              <!-- Toolbar (Caddyfile actions) -->
              <div class="flex flex-wrap items-center justify-between gap-2 rounded-xl border border-slate-200 bg-slate-50 p-2.5">
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
                    :disabled="formatting || caddyLoading || !!caddyLoadError"
                    :title="caddyLoadError ? '请先解决 Caddyfile 加载错误后再格式化' : '使用 caddy fmt 格式化'"
                    class="inline-flex items-center gap-1.5 rounded-lg border border-slate-200 bg-white px-2.5 py-1.5 text-xs font-medium text-slate-700 hover:bg-slate-50 disabled:cursor-not-allowed disabled:opacity-50"
                    @click="handleFormat"
                  >
                    <Wand2 class="h-3.5 w-3.5" />
                    {{ formatting ? '格式化中...' : '格式化 (fmt)' }}
                  </button>
                  <button
                    type="button"
                    :disabled="validating || caddyLoading || !!caddyLoadError"
                    :title="caddyLoadError ? '请先解决 Caddyfile 加载错误后再预校验' : '使用 caddy validate 校验语法'"
                    class="inline-flex items-center gap-1.5 rounded-lg border border-slate-200 bg-white px-2.5 py-1.5 text-xs font-medium text-slate-700 hover:bg-slate-50 disabled:cursor-not-allowed disabled:opacity-50"
                    @click="handleValidate"
                  >
                    <CheckCircle2 class="h-3.5 w-3.5 text-emerald-600" />
                    {{ validating ? '校验中...' : '预校验 (validate)' }}
                  </button>
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
                    class="inline-flex items-center gap-1 rounded-lg border px-2.5 py-1.5 text-xs font-medium transition"
                    :class="caddyLineWrap ? 'border-indigo-300 bg-indigo-50 text-indigo-700' : 'border-slate-200 bg-white text-slate-700 hover:bg-slate-50'"
                    @click="caddyLineWrap = !caddyLineWrap"
                  >
                    <WrapText class="h-3.5 w-3.5" />
                    自动换行
                  </button>
                </div>

                <button
                  type="button"
                  :disabled="publishing || caddyLoading || !!caddyLoadError"
                  title="写入宿主机 Caddyfile 并热重载 Caddy 容器"
                  class="inline-flex items-center gap-1.5 rounded-lg bg-indigo-600 px-3.5 py-1.5 text-xs font-semibold text-white shadow-sm hover:bg-indigo-700 disabled:cursor-not-allowed disabled:opacity-50"
                  @click="handlePublish(false)"
                >
                  <Save class="h-3.5 w-3.5" />
                  {{ publishing ? '发布中...' : `保存并重载 (${saveShortcutLabel})` }}
                </button>
              </div>

              <!-- Meta info + Summary input -->
              <div class="flex flex-wrap items-center justify-between gap-3 text-xs text-slate-500">
                <div class="flex flex-wrap items-center gap-2 font-mono text-[11px]">
                  <span class="break-all">路径: {{ caddyHostPath || selectedHost.caddy_host_caddyfile }}</span>
                  <span
                    v-if="caddyMountType"
                    class="rounded bg-slate-100 px-1.5 py-0.5 text-slate-700"
                    :title="caddyMountType === 'dir' ? '目录挂载：支持临时文件原子替换' : caddyMountType === 'file' ? '单文件挂载：采用原地覆写以保持 inode 不变' : '挂载模式'"
                  >
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
                class="space-y-3 rounded-xl border border-rose-200 bg-rose-50 p-4 text-xs text-rose-800"
              >
                <div class="flex flex-wrap items-center justify-between gap-2">
                  <div>
                    <div class="font-semibold">拉取 Caddyfile 失败</div>
                    <div class="mt-1 font-mono break-all text-rose-700">{{ caddyLoadError }}</div>
                  </div>
                  <div class="flex flex-wrap items-center gap-2">
                    <button
                      type="button"
                      :disabled="discovering"
                      class="inline-flex items-center gap-1 rounded-lg border border-indigo-300 bg-white px-2.5 py-1.5 text-xs font-medium text-indigo-700 hover:bg-indigo-50"
                      @click="handleDiscoverCaddy()"
                    >
                      <Search class="h-3.5 w-3.5" />
                      自动探测路径
                    </button>
                    <button
                      v-if="!selectedHost.is_local"
                      type="button"
                      class="inline-flex items-center gap-1 rounded-lg bg-indigo-600 px-2.5 py-1.5 text-xs font-semibold text-white hover:bg-indigo-700"
                      @click="initStarterCaddyfile"
                    >
                      <Plus class="h-3.5 w-3.5" />
                      用最小模板初始化编辑
                    </button>
                  </div>
                </div>

                <div
                  v-if="activeDiagnosticGuide"
                  class="space-y-2 rounded-lg border border-amber-200 bg-amber-50 p-3 text-amber-950"
                >
                  <div class="font-semibold">{{ activeDiagnosticGuide.title }}</div>
                  <p class="leading-relaxed text-amber-900">{{ activeDiagnosticGuide.summary }}</p>
                  <div v-for="cmd in activeDiagnosticGuide.commands" :key="cmd.label" class="space-y-1">
                    <div class="flex items-center justify-between text-[11px] font-medium">
                      <span>{{ cmd.label }}</span>
                      <button
                        type="button"
                        class="inline-flex items-center gap-1 rounded bg-white px-2 py-0.5 text-[11px] font-semibold text-indigo-700 ring-1 ring-amber-300 hover:bg-indigo-50"
                        @click="copyCommand(cmd.label, cmd.code)"
                      >
                        <Copy class="h-3 w-3" />
                        复制
                      </button>
                    </div>
                    <pre class="overflow-x-auto rounded bg-slate-900 p-2.5 font-mono text-[11px] text-slate-100">{{ cmd.code }}</pre>
                  </div>
                </div>
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

              <!-- Editor + Deployed Certs TLS Snippet Picker & Site Block Generator -->
              <div class="grid gap-4 xl:grid-cols-12">
                <div class="relative h-[480px] min-w-0 xl:col-span-8">
                  <div
                    v-if="caddyLoading"
                    class="absolute inset-0 z-10 flex flex-col items-center justify-center gap-2 rounded-lg bg-white/85 backdrop-blur-[1px]"
                  >
                    <Loader2 class="h-6 w-6 animate-spin text-indigo-600" />
                    <span class="text-xs font-medium text-slate-600">正在拉取线上 Caddyfile...</span>
                  </div>
                  <Suspense>
                    <CaddyEditor
                      ref="caddyEditorRef"
                      v-model="caddyContent"
                      :error-line="caddyErrorLine"
                      :line-wrap="caddyLineWrap"
                      @save="handlePublish(false)"
                    />
                    <template #fallback>
                      <div class="flex h-full items-center justify-center rounded-lg border border-slate-200 bg-slate-50 text-xs text-slate-500">
                        正在加载编辑器组件...
                      </div>
                    </template>
                  </Suspense>
                </div>

                <div class="flex min-w-0 flex-col gap-3 rounded-xl border border-slate-200 bg-slate-50/70 p-4 xl:col-span-4">
                  <!-- Reverse Proxy Site Generator -->
                  <div class="space-y-2.5 rounded-lg border border-indigo-100 bg-white p-3">
                    <div class="flex items-center gap-1.5 text-xs font-semibold text-slate-900">
                      <Sparkles class="h-3.5 w-3.5 text-indigo-600" />
                      快速生成反代站点块
                    </div>
                    <div class="space-y-2">
                      <input
                        v-model="siteGenForm.domain"
                        type="text"
                        placeholder="站点域名，如 app.example.com"
                        class="w-full rounded border border-slate-300 px-2.5 py-1.5 font-mono text-xs focus:border-indigo-500 focus:outline-none"
                      />
                      <input
                        v-model="siteGenForm.upstream"
                        type="text"
                        placeholder="反代上游地址，如 127.0.0.1:8080"
                        class="w-full rounded border border-slate-300 px-2.5 py-1.5 font-mono text-xs focus:border-indigo-500 focus:outline-none"
                      />
                      <select
                        v-if="hostDeployments.length > 0"
                        v-model.number="siteGenForm.deploymentId"
                        class="w-full rounded border border-slate-300 bg-white px-2.5 py-1.5 text-xs focus:border-indigo-500 focus:outline-none"
                      >
                        <option v-for="d in hostDeployments" :key="d.id" :value="d.id">
                          自动引用证书: {{ d.cert_domain || d.name }}
                        </option>
                        <option :value="0">不绑定自定义 tls 路径（使用 Caddy 自动 HTTPS）</option>
                      </select>
                      <div class="flex items-center justify-between gap-2">
                        <label class="flex cursor-pointer items-center gap-1.5 text-[11px] text-slate-600">
                          <input v-model="siteGenForm.enableEncode" type="checkbox" class="rounded text-indigo-600" />
                          启用 gzip 压缩
                        </label>
                        <button
                          type="button"
                          class="rounded-lg bg-indigo-600 px-2.5 py-1 text-[11px] font-semibold text-white hover:bg-indigo-700"
                          @click="insertReverseProxyBlock"
                        >
                          插入站点块
                        </button>
                      </div>
                    </div>
                  </div>

                  <div class="flex items-center gap-2 pt-1">
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
                  <div v-else class="custom-scrollbar max-h-[250px] space-y-2 overflow-y-auto pr-1">
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
      :subtitle="editingHost ? '编辑时 SSH 密钥/密码留空表示保留原加密值不变' : '填写 SSH 连接信息后可先测试连通性并自动探测 Caddy 路径'"
      max-width="2xl"
      @close="hostModalOpen = false"
    >
      <form id="host-modal-form" class="space-y-4" @submit.prevent="submitHost">
        <div class="grid gap-4 sm:grid-cols-2">
          <div>
            <label for="host-name" class="mb-1 block text-xs font-medium text-slate-700">主机名称 *</label>
            <input
              id="host-name"
              v-model="hostForm.name"
              type="text"
              placeholder="例如：edge-hk-1"
              class="w-full rounded-lg border border-slate-300 px-3 py-2 text-sm focus:border-indigo-500 focus:outline-none"
            />
          </div>
          <template v-if="!editingHost?.is_local">
            <div>
              <label for="host-addr" class="mb-1 block text-xs font-medium text-slate-700">主机 IP / 域名 *</label>
              <input
                id="host-addr"
                v-model="hostForm.host"
                type="text"
                placeholder="10.0.0.10"
                class="w-full rounded-lg border border-slate-300 px-3 py-2 font-mono text-sm focus:border-indigo-500 focus:outline-none"
              />
            </div>
          </template>
        </div>

        <template v-if="!editingHost?.is_local">
          <div class="grid gap-4 sm:grid-cols-2">
            <div>
              <label for="host-user" class="mb-1 block text-xs font-medium text-slate-700">SSH 用户名</label>
              <input
                id="host-user"
                v-model="hostForm.username"
                type="text"
                class="w-full rounded-lg border border-slate-300 px-3 py-2 font-mono text-sm"
              />
            </div>
            <div>
              <label for="host-port" class="mb-1 block text-xs font-medium text-slate-700">SSH 端口</label>
              <input
                id="host-port"
                v-model.number="hostForm.port"
                type="number"
                min="1"
                max="65535"
                class="w-full rounded-lg border border-slate-300 px-3 py-2 font-mono text-sm tabular-nums"
              />
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
                <div class="mb-1 flex items-center justify-between">
                  <label for="host-privkey" class="text-xs font-medium text-slate-700">
                    SSH 私钥 (OpenSSH / PEM) {{ editingHost ? '（留空保持原私钥）' : '' }}
                  </label>
                  <label class="inline-flex cursor-pointer items-center gap-1 text-xs font-medium text-indigo-600 hover:text-indigo-700">
                    <Upload class="h-3 w-3" />
                    从文件读取
                    <input type="file" accept=".pem,.key,.txt,id_rsa,id_ed25519" class="hidden" @change="handleSSHKeyFileSelect" />
                  </label>
                </div>
                <textarea
                  id="host-privkey"
                  v-model="hostForm.ssh_private_key"
                  rows="3"
                  placeholder="-----BEGIN OPENSSH PRIVATE KEY-----"
                  class="w-full rounded-lg border border-slate-300 bg-white px-3 py-2 font-mono text-xs"
                />
              </div>
              <div>
                <label for="host-passphrase" class="mb-1 block text-xs font-medium text-slate-700">私钥口令 Passphrase（可选）</label>
                <input
                  id="host-passphrase"
                  v-model="hostForm.ssh_passphrase"
                  type="password"
                  placeholder="如私钥无密码请留空"
                  class="w-full rounded-lg border border-slate-300 bg-white px-3 py-2 font-mono text-xs"
                />
              </div>
            </template>

            <div v-else>
              <label for="host-password" class="mb-1 block text-xs font-medium text-slate-700">
                SSH 登录密码 {{ editingHost ? '（留空保持原密码）' : '' }}
              </label>
              <input
                id="host-password"
                v-model="hostForm.ssh_password"
                type="password"
                class="w-full rounded-lg border border-slate-300 bg-white px-3 py-2 font-mono text-xs"
              />
            </div>
          </div>
        </template>

        <!-- Caddy Docker Profile -->
        <div class="space-y-3 rounded-xl border border-slate-200 bg-slate-50 p-4">
          <div class="flex flex-wrap items-center justify-between gap-2">
            <span class="text-xs font-semibold text-slate-800">Caddy Docker 档案</span>
            <label class="flex cursor-pointer items-center gap-1.5 text-xs text-slate-700">
              <input v-model="hostForm.caddy_enabled" type="checkbox" class="rounded text-indigo-600" />
              启用 Caddy 管理工作台
            </label>
          </div>
          <div v-if="hostForm.caddy_enabled" class="space-y-3">
            <div
              v-if="editingHost?.is_local"
              class="rounded-lg border border-amber-200 bg-amber-50 px-3 py-2 text-[11px] leading-relaxed text-amber-800"
            >
              Docker 部署下使用内置 <code class="font-mono">Local</code> 模式时，请确保在
              <code class="font-mono">docker-compose.yml</code> 中同时挂载
              <code class="font-mono">/var/run/docker.sock</code> 以及宿主机 Caddyfile 目录与证书目录（容器内外路径保持一致）。
            </div>
            <div>
              <label for="host-caddy-container" class="mb-1 block text-[11px] font-medium text-slate-600">容器名称</label>
              <input
                id="host-caddy-container"
                v-model="hostForm.caddy_container"
                type="text"
                class="w-full rounded border border-slate-300 bg-white px-2.5 py-1.5 font-mono text-xs"
              />
            </div>
          </div>
        </div>

        <!-- Inline Probe Result -->
        <div
          v-if="modalProbeResult"
          class="space-y-2 rounded-xl border p-3.5 text-xs"
          :class="
            modalProbeResult.ssh_ok && (!hostForm.caddy_enabled || (modalProbeResult.docker_ok && modalProbeResult.caddy_running))
              ? 'border-emerald-200 bg-emerald-50 text-emerald-900'
              : 'border-amber-200 bg-amber-50 text-amber-950'
          "
        >
          <div class="flex flex-wrap items-center justify-between gap-2 font-semibold">
            <span>{{ modalProbeResult.message }}</span>
            <button
              v-if="modalProbeResult.detected_caddy_config"
              type="button"
              class="rounded-lg bg-indigo-600 px-2.5 py-1 text-[11px] font-semibold text-white hover:bg-indigo-700"
              @click="applyDetectedCaddyToForm(modalProbeResult.detected_caddy_config)"
            >
              回填「{{ modalProbeResult.detected_caddy_config.container_name }}」路径
            </button>
          </div>
          <div v-if="modalProbeResult.detected_containers && modalProbeResult.detected_containers.length > 0" class="flex flex-wrap gap-1.5 pt-1">
            <button
              v-for="c in modalProbeResult.detected_containers"
              :key="c.name"
              type="button"
              class="rounded border border-slate-300 bg-white px-2 py-0.5 font-mono text-[11px] hover:border-indigo-400"
              @click="handleProbeInModal(c.name)"
            >
              {{ c.name }} ({{ c.state }})
            </button>
          </div>
        </div>

        <!-- Collapsible Advanced Settings -->
        <div class="rounded-xl border border-slate-200 bg-white">
          <button
            type="button"
            class="flex w-full items-center justify-between px-4 py-2.5 text-xs font-semibold text-slate-700 hover:bg-slate-50"
            @click="hostAdvancedOpen = !hostAdvancedOpen"
          >
            <span>高级设置（Host Key 策略 / 自定义 Caddy 路径）</span>
            <ChevronUp v-if="hostAdvancedOpen" class="h-4 w-4 text-slate-400" />
            <ChevronDown v-else class="h-4 w-4 text-slate-400" />
          </button>
          <div v-if="hostAdvancedOpen" class="space-y-3 border-t border-slate-100 p-4">
            <div v-if="!editingHost?.is_local">
              <label for="host-key-policy" class="mb-1 block text-[11px] font-medium text-slate-600">SSH Host Key 策略</label>
              <select
                id="host-key-policy"
                v-model="hostForm.host_key_policy"
                class="w-full rounded border border-slate-300 bg-white px-2.5 py-1.5 text-xs"
              >
                <option value="tofu">TOFU (首次信任锁定)</option>
                <option value="strict">Strict (严格比对)</option>
                <option value="insecure">Insecure (跳过校验)</option>
              </select>
            </div>
            <div v-if="hostForm.caddy_enabled" class="grid gap-3 sm:grid-cols-2">
              <div>
                <label for="host-caddyfile" class="mb-1 block text-[11px] font-medium text-slate-600">宿主机 Caddyfile 路径</label>
                <input id="host-caddyfile" v-model="hostForm.caddy_host_caddyfile" type="text" class="w-full rounded border border-slate-300 bg-white px-2.5 py-1.5 font-mono text-xs" />
              </div>
              <div>
                <label for="container-caddyfile" class="mb-1 block text-[11px] font-medium text-slate-600">容器内 Caddyfile 路径</label>
                <input id="container-caddyfile" v-model="hostForm.caddy_container_caddyfile" type="text" class="w-full rounded border border-slate-300 bg-white px-2.5 py-1.5 font-mono text-xs" />
              </div>
              <div>
                <label for="host-certdir" class="mb-1 block text-[11px] font-medium text-slate-600">宿主机证书根目录</label>
                <input id="host-certdir" v-model="hostForm.caddy_host_cert_dir" type="text" class="w-full rounded border border-slate-300 bg-white px-2.5 py-1.5 font-mono text-xs" />
              </div>
              <div>
                <label for="container-certdir" class="mb-1 block text-[11px] font-medium text-slate-600">容器内证书挂载根目录</label>
                <input id="container-certdir" v-model="hostForm.caddy_container_cert_dir" type="text" class="w-full rounded border border-slate-300 bg-white px-2.5 py-1.5 font-mono text-xs" />
              </div>
            </div>
          </div>
        </div>
      </form>

      <template #footer>
        <button
          type="button"
          :disabled="modalProbing"
          class="mr-auto inline-flex items-center gap-1.5 rounded-lg border border-indigo-200 bg-indigo-50 px-3.5 py-2 text-xs font-semibold text-indigo-700 hover:bg-indigo-100 disabled:opacity-50"
          @click="handleProbeInModal()"
        >
          <Sparkles class="h-3.5 w-3.5" />
          {{ modalProbing ? '探测中...' : '测试连接 & 探测路径' }}
        </button>
        <button
          type="button"
          class="rounded-lg border border-slate-300 bg-white px-4 py-2 text-sm font-medium text-slate-700 hover:bg-slate-50"
          @click="hostModalOpen = false"
        >
          取消
        </button>
        <button
          type="submit"
          form="host-modal-form"
          :disabled="hostSaving"
          class="rounded-lg bg-indigo-600 px-4 py-2 text-sm font-semibold text-white hover:bg-indigo-700 disabled:opacity-50"
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
              <td class="px-3 py-3 font-mono font-semibold text-slate-800">
                <span>v{{ s.version }}</span>
                <span
                  v-if="expectedSHA256 && s.sha256 === expectedSHA256"
                  class="ml-1.5 rounded bg-emerald-100 px-1.5 py-0.5 font-sans text-[10px] font-semibold text-emerald-700"
                >
                  当前线上
                </span>
              </td>
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
                    :disabled="Boolean(expectedSHA256 && s.sha256 === expectedSHA256)"
                    class="rounded border border-indigo-200 bg-indigo-50 px-2.5 py-1 font-medium text-indigo-700 hover:bg-indigo-100 disabled:cursor-not-allowed disabled:opacity-40"
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
          <div class="flex flex-wrap items-center justify-between gap-2 border-b border-slate-800 px-4 py-2 text-xs text-slate-400">
            <span>docker logs (最近输出)</span>
            <div class="flex flex-wrap items-center gap-2">
              <input
                v-model="containerLogSearch"
                type="text"
                placeholder="筛选关键字..."
                class="rounded border border-slate-700 bg-slate-900 px-2 py-1 text-[11px] text-slate-200 placeholder-slate-500 focus:border-indigo-500 focus:outline-none"
              />
              <button
                type="button"
                class="rounded border px-2 py-1 text-[11px]"
                :class="containerLogPretty ? 'border-indigo-500 bg-indigo-950 text-indigo-300' : 'border-slate-700 text-slate-300 hover:bg-slate-900'"
                @click="containerLogPretty = !containerLogPretty"
              >
                JSON 格式化
              </button>
              <button
                type="button"
                class="inline-flex items-center gap-1 text-slate-300 hover:text-white"
                @click="copyCommand('容器日志', filteredContainerLogs)"
              >
                <Copy class="h-3 w-3" />
                复制
              </button>
              <button
                type="button"
                :disabled="containerLoading"
                class="inline-flex items-center gap-1 text-indigo-400 hover:text-indigo-300"
                @click="refreshContainerInfo"
              >
                <RefreshCw class="h-3 w-3" :class="containerLoading ? 'animate-spin' : ''" />
                刷新
              </button>
            </div>
          </div>
          <pre class="custom-scrollbar max-h-80 overflow-auto p-4 font-mono text-xs leading-5 text-slate-200 whitespace-pre-wrap">{{ filteredContainerLogs }}</pre>
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
              <span
                class="rounded px-2 py-0.5 font-medium"
                :class="
                  !logsTargetTlsEnabled
                    ? 'bg-slate-200 text-slate-600'
                    : log.tls_verified
                      ? 'bg-emerald-100 text-emerald-800'
                      : 'bg-amber-100 text-amber-800'
                "
              >
                TLS 校验: {{ !logsTargetTlsEnabled ? '未开启' : log.tls_verified ? '已通过' : '未通过' }}
              </span>
            </div>
            <span class="font-mono text-[11px] text-slate-500 tabular-nums">{{ formatDateTime(log.started_at) }}</span>
          </div>
          <div
            v-if="log.error_message"
            class="mt-2 rounded px-2.5 py-1.5 break-words"
            :class="log.status === 'success' ? 'bg-amber-50 text-amber-800' : 'bg-rose-50 text-rose-700'"
          >
            {{ log.error_message }}
          </div>
          <pre v-if="log.stdout" class="mt-2 max-h-32 overflow-auto rounded bg-slate-900 p-2 font-mono text-[11px] text-emerald-300">{{ log.stdout }}</pre>
          <pre
            v-if="log.stderr && log.stderr.trim() !== (log.error_message || '').trim()"
            class="mt-2 max-h-32 overflow-auto rounded bg-slate-900 p-2 font-mono text-[11px]"
            :class="log.status === 'success' ? 'text-slate-300' : 'text-rose-300'"
          >{{ log.stderr }}</pre>
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

    <!-- Quick Bind Certificate Modal -->
    <ModalDialog
      :open="bindCertModalOpen"
      :title="`绑定证书到主机 — ${selectedHost?.name || ''}`"
      subtitle="选择证书后将自动派生证书写入路径与热重载命令"
      max-width="lg"
      @close="bindCertModalOpen = false"
    >
      <div v-if="allCertsLoading" class="py-8 text-center text-sm text-slate-500">
        加载证书列表...
      </div>
      <div v-else-if="allCerts.length === 0" class="py-8 text-center text-xs text-slate-500">
        暂无可用证书，请先前往「证书管理」创建证书。
      </div>
      <form v-else id="bind-cert-form" class="space-y-4" @submit.prevent="submitBindCert">
        <div>
          <label for="bind-cert-id" class="mb-1 block text-xs font-medium text-slate-700">选择证书 *</label>
          <select
            id="bind-cert-id"
            v-model.number="bindForm.certificate_id"
            class="w-full rounded-lg border border-slate-300 bg-white px-3 py-2 text-sm"
          >
            <option v-for="c in allCerts" :key="c.id" :value="c.id">
              {{ c.domain }} ({{ c.status }})
            </option>
          </select>
        </div>
        <div class="grid gap-4 sm:grid-cols-2">
          <div>
            <label for="bind-template" class="mb-1 block text-xs font-medium text-slate-700">部署模板</label>
            <select
              id="bind-template"
              v-model="bindForm.template"
              class="w-full rounded-lg border border-slate-300 bg-white px-3 py-2 text-sm"
            >
              <option value="caddy_docker">Caddy (Docker)</option>
              <option value="local_dir">仅输出证书文件</option>
              <option value="custom_ssh">自定义 SSH 命令</option>
            </select>
          </div>
          <div>
            <label for="bind-name" class="mb-1 block text-xs font-medium text-slate-700">目标名称</label>
            <input
              id="bind-name"
              v-model="bindForm.name"
              type="text"
              class="w-full rounded-lg border border-slate-300 px-3 py-2 text-sm"
            />
          </div>
        </div>
      </form>
      <template #footer>
        <button
          type="button"
          class="rounded-lg border border-slate-300 bg-white px-4 py-2 text-sm font-medium text-slate-700 hover:bg-slate-50"
          @click="bindCertModalOpen = false"
        >
          取消
        </button>
        <button
          v-if="allCerts.length > 0"
          type="submit"
          form="bind-cert-form"
          :disabled="bindSaving"
          class="rounded-lg bg-indigo-600 px-4 py-2 text-sm font-semibold text-white hover:bg-indigo-700 disabled:opacity-50"
        >
          {{ bindSaving ? '绑定中...' : '确认绑定' }}
        </button>
      </template>
    </ModalDialog>

    <!-- Dirty Draft Host Switch Confirmation -->
    <ConfirmDialog
      :open="dirtySwitchConfirmOpen"
      title="放弃未保存的 Caddyfile 草稿？"
      :message="`当前编辑内容尚未保存发布，切换到主机「${pendingSwitchHost?.name || ''}」将丢失草稿。`"
      confirm-text="丢弃并切换"
      danger
      @confirm="confirmSwitchHost"
      @cancel="dirtySwitchConfirmOpen = false"
    />

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
