<script setup lang="ts">
import { computed, ref } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import {
  Activity,
  KeyRound,
  LayoutDashboard,
  Lock,
  LogOut,
  Menu,
  Server,
  Settings,
  ShieldCheck,
  X,
} from 'lucide-vue-next'
import { authState, clearAuthState } from '@/stores/auth'
import { toastState } from '@/stores/toast'
import { logout } from '@/api/auth'
import { showToast } from '@/stores/toast'

const route = useRoute()
const router = useRouter()
const mobileOpen = ref(false)
const loggingOut = ref(false)

const navItems = [
  { name: 'dashboard', path: '/', label: '概览', icon: LayoutDashboard },
  { name: 'certificates', path: '/certificates', label: '证书管理', icon: ShieldCheck },
  { name: 'hosts', path: '/hosts', label: '主机与 Caddy', icon: Server },
  { name: 'credentials', path: '/credentials', label: '凭据中心', icon: KeyRound },
  { name: 'settings', path: '/settings', label: '系统设置', icon: Settings },
]

const currentTitle = computed(() => {
  const found = navItems.find((item) => item.path === route.path)
  if (found) return found.label
  if (route.path === '/change-password') return '修改管理员密码'
  return 'SSL Center'
})

async function handleLogout() {
  loggingOut.value = true
  try {
    await logout()
  } catch {
    // ignore logout error, clear local state anyway
  } finally {
    clearAuthState()
    loggingOut.value = false
    showToast('info', '已安全退出登录')
    await router.push('/login')
  }
}
</script>

<template>
  <div class="flex min-h-screen bg-slate-50 text-slate-900">
    <!-- Mobile backdrop -->
    <div
      v-if="mobileOpen"
      class="fixed inset-0 z-30 bg-slate-900/40 lg:hidden"
      @click="mobileOpen = false"
    />

    <!-- Sidebar -->
    <aside
      class="fixed inset-y-0 left-0 z-40 flex w-64 flex-col border-r border-slate-200 bg-white transition-transform duration-200 lg:static lg:translate-x-0"
      :class="mobileOpen ? 'translate-x-0' : '-translate-x-full'"
    >
      <div class="flex h-16 items-center justify-between border-b border-slate-200 px-5">
        <router-link to="/" class="flex items-center gap-2.5">
          <div class="flex h-9 w-9 items-center justify-center rounded-xl bg-indigo-600 text-white shadow-sm">
            <ShieldCheck class="h-5 w-5" />
          </div>
          <div>
            <div class="text-sm font-bold tracking-tight text-slate-900">SSL Center</div>
            <div class="text-[11px] font-medium text-slate-500">ACME &amp; Caddy 运维中心</div>
          </div>
        </router-link>
        <button
          type="button"
          class="rounded-lg p-1 text-slate-400 hover:bg-slate-100 lg:hidden"
          @click="mobileOpen = false"
        >
          <X class="h-5 w-5" />
        </button>
      </div>

      <nav class="flex-1 space-y-1 px-3 py-4">
        <router-link
          v-for="item in navItems"
          :key="item.path"
          :to="item.path"
          class="flex items-center gap-3 rounded-lg px-3 py-2.5 text-sm font-medium transition"
          :class="
            route.path === item.path
              ? 'bg-indigo-50 text-indigo-700'
              : 'text-slate-600 hover:bg-slate-100 hover:text-slate-900'
          "
          @click="mobileOpen = false"
        >
          <component
            :is="item.icon"
            class="h-4 w-4 shrink-0"
            :class="route.path === item.path ? 'text-indigo-600' : 'text-slate-400'"
          />
          <span>{{ item.label }}</span>
        </router-link>
      </nav>

      <div class="border-t border-slate-200 p-4">
        <div class="mb-3 rounded-lg bg-slate-50 px-3 py-2 text-xs text-slate-500">
          <div class="flex items-center justify-between">
            <span class="font-medium text-slate-700">管理员会话</span>
            <span class="inline-flex items-center gap-1 text-emerald-600">
              <Activity class="h-3 w-3" />
              在线
            </span>
          </div>
          <div class="mt-1 font-mono text-[11px] text-slate-500 tabular-nums">
            IP: {{ authState.ip || '未知' }}
          </div>
        </div>

        <div class="flex items-center gap-2">
          <router-link
            to="/change-password"
            class="flex flex-1 items-center justify-center gap-1.5 rounded-lg border border-slate-200 bg-white px-2.5 py-1.5 text-xs font-medium text-slate-700 transition hover:bg-slate-50"
            @click="mobileOpen = false"
          >
            <Lock class="h-3.5 w-3.5 text-slate-400" />
            改密
          </router-link>
          <button
            type="button"
            class="flex flex-1 items-center justify-center gap-1.5 rounded-lg border border-slate-200 bg-white px-2.5 py-1.5 text-xs font-medium text-slate-700 transition hover:border-rose-200 hover:bg-rose-50 hover:text-rose-700"
            :disabled="loggingOut"
            @click="handleLogout"
          >
            <LogOut class="h-3.5 w-3.5" />
            退出
          </button>
        </div>
      </div>
    </aside>

    <!-- Main area -->
    <div class="flex min-w-0 flex-1 flex-col">
      <!-- Maintenance banner -->
      <div
        v-if="toastState.maintenanceActive"
        class="border-b border-amber-200 bg-amber-50 px-4 py-2.5 text-center text-xs font-medium text-amber-800"
      >
        {{ toastState.maintenanceMessage }}
      </div>

      <!-- Top bar (mobile + page title) -->
      <header class="flex h-14 items-center justify-between border-b border-slate-200 bg-white px-4 sm:px-6 lg:hidden">
        <div class="flex items-center gap-3">
          <button
            type="button"
            class="rounded-lg p-1.5 text-slate-600 hover:bg-slate-100"
            @click="mobileOpen = true"
          >
            <Menu class="h-5 w-5" />
          </button>
          <span class="text-sm font-semibold text-slate-900">{{ currentTitle }}</span>
        </div>
      </header>

      <main class="flex-1 px-4 py-6 sm:px-6 lg:px-8">
        <div class="mx-auto max-w-7xl">
          <slot />
        </div>
      </main>
    </div>
  </div>
</template>
