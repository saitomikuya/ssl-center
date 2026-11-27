import { createRouter, createWebHistory } from 'vue-router'
import { getMe } from '@/api/auth'
import { applyAuthMe, authState, clearAuthState } from '@/stores/auth'

const LoginView = () => import('@/views/LoginView.vue')
const ChangePasswordView = () => import('@/views/ChangePasswordView.vue')
const DashboardView = () => import('@/views/DashboardView.vue')
const CertificatesView = () => import('@/views/CertificatesView.vue')
const HostsView = () => import('@/views/HostsView.vue')
const CredentialsView = () => import('@/views/CredentialsView.vue')
const SettingsView = () => import('@/views/SettingsView.vue')

export const router = createRouter({
  history: createWebHistory(),
  routes: [
    { path: '/login', name: 'login', component: LoginView, meta: { public: true } },
    {
      path: '/change-password',
      name: 'change-password',
      component: ChangePasswordView,
      meta: { allowMustChange: true },
    },
    { path: '/', name: 'dashboard', component: DashboardView },
    { path: '/certificates', name: 'certificates', component: CertificatesView },
    { path: '/hosts', name: 'hosts', component: HostsView },
    { path: '/credentials', name: 'credentials', component: CredentialsView },
    { path: '/settings', name: 'settings', component: SettingsView },
    { path: '/:pathMatch(.*)*', redirect: '/' },
  ],
})

async function ensureAuthChecked() {
  if (authState.checked) return
  try {
    const me = await getMe()
    applyAuthMe(me)
  } catch {
    clearAuthState()
  }
}

router.beforeEach(async (to) => {
  await ensureAuthChecked()

  if (to.meta.public) {
    if (authState.authenticated) {
      return authState.mustChangePassword ? '/change-password' : '/'
    }
    return true
  }

  if (!authState.authenticated) {
    return { path: '/login', query: to.fullPath !== '/' ? { redirect: to.fullPath } : undefined }
  }

  if (authState.mustChangePassword && !to.meta.allowMustChange) {
    return '/change-password'
  }

  return true
})
