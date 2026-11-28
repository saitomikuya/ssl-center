<script setup lang="ts">
import { onMounted, onUnmounted, ref } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { Eye, EyeOff, Lock, ShieldCheck } from 'lucide-vue-next'
import { login } from '@/api/auth'
import { ApiError } from '@/api/client'
import { applyAuthMe } from '@/stores/auth'
import { showToast } from '@/stores/toast'
import type { RateLimitDetails } from '@/types/api'

const route = useRoute()
const router = useRouter()

const passwordInputRef = ref<HTMLInputElement | null>(null)
const password = ref('')
const showPassword = ref(false)
const loading = ref(false)
const errorMsg = ref('')
const retrySeconds = ref(0)
let countdownTimer: number | null = null

onMounted(() => {
  passwordInputRef.value?.focus()
})

function startCountdown(seconds: number) {
  if (countdownTimer) window.clearInterval(countdownTimer)
  retrySeconds.value = Math.max(1, seconds)
  countdownTimer = window.setInterval(() => {
    if (retrySeconds.value <= 1) {
      retrySeconds.value = 0
      if (countdownTimer) {
        window.clearInterval(countdownTimer)
        countdownTimer = null
      }
    } else {
      retrySeconds.value -= 1
    }
  }, 1000)
}

onUnmounted(() => {
  if (countdownTimer) window.clearInterval(countdownTimer)
})

async function handleSubmit() {
  if (!password.value) {
    errorMsg.value = '请输入管理员密码'
    return
  }
  loading.value = true
  errorMsg.value = ''
  try {
    const res = await login({ password: password.value })
    applyAuthMe(res)
    if (res.must_change_password) {
      showToast('warning', '请先修改初始密码后再继续使用控制台')
      await router.replace('/change-password')
      return
    }
    showToast('success', '登录成功')
    const redirect = typeof route.query.redirect === 'string' ? route.query.redirect : '/'
    await router.replace(redirect)
  } catch (err) {
    if (err instanceof ApiError) {
      if (err.code === 'RATE_LIMITED') {
        const details = err.details as RateLimitDetails | undefined
        const secs = details?.retry_after_seconds || 60
        startCountdown(secs)
        errorMsg.value = `登录失败次数过多，请在 ${secs} 秒后重试`
      } else if (err.status === 401) {
        errorMsg.value = '管理员密码错误，请重试'
      } else {
        errorMsg.value = err.message
      }
    } else {
      errorMsg.value = '网络异常，请检查服务是否运行'
    }
  } finally {
    loading.value = false
  }
}
</script>

<template>
  <div class="flex min-h-screen flex-col items-center justify-center bg-slate-50 px-4 py-12">
    <div class="w-full max-w-md rounded-2xl border border-slate-200 bg-white p-8 shadow-sm">
      <div class="mb-7 flex flex-col items-center text-center">
        <div class="mb-3 flex h-12 w-12 items-center justify-center rounded-2xl bg-indigo-600 text-white shadow-md shadow-indigo-600/20">
          <ShieldCheck class="h-6 w-6" />
        </div>
        <h1 class="text-xl font-bold text-slate-900">SSL Center 运维控制台</h1>
        <p class="mt-1 text-sm text-slate-500">ACME 证书签发与 Caddy 自动化运维中心</p>
      </div>

      <form class="space-y-5" @submit.prevent="handleSubmit">
        <input
          type="text"
          name="username"
          value="admin"
          autocomplete="username"
          tabindex="-1"
          aria-hidden="true"
          class="sr-only"
          readonly
        />
        <div>
          <label for="login-password" class="mb-1.5 block text-sm font-medium text-slate-700">
            管理员密码
          </label>
          <div class="relative">
            <div class="pointer-events-none absolute inset-y-0 left-0 flex items-center pl-3 text-slate-400">
              <Lock class="h-4 w-4" />
            </div>
            <input
              id="login-password"
              ref="passwordInputRef"
              v-model="password"
              name="password"
              :type="showPassword ? 'text' : 'password'"
              autocomplete="current-password"
              placeholder="请输入管理员密码"
              class="block w-full rounded-lg border border-slate-300 bg-white py-2.5 pl-10 pr-10 text-sm text-slate-900 placeholder-slate-400 focus:border-indigo-500 focus:outline-none focus:ring-2 focus:ring-indigo-500/20"
            />
            <button
              type="button"
              :aria-label="showPassword ? '隐藏密码' : '显示密码'"
              class="absolute inset-y-0 right-0 flex items-center pr-3 text-slate-400 hover:text-slate-600"
              @click="showPassword = !showPassword"
            >
              <EyeOff v-if="showPassword" class="h-4 w-4" />
              <Eye v-else class="h-4 w-4" />
            </button>
          </div>
        </div>

        <div
          v-if="errorMsg"
          class="rounded-lg border border-rose-200 bg-rose-50 px-3.5 py-2.5 text-xs font-medium text-rose-700"
        >
          {{ errorMsg }}
          <span v-if="retrySeconds > 0" class="ml-1 font-mono tabular-nums">({{ retrySeconds }}s)</span>
        </div>

        <button
          type="submit"
          :disabled="loading || retrySeconds > 0"
          class="flex w-full items-center justify-center rounded-lg bg-indigo-600 px-4 py-2.5 text-sm font-semibold text-white shadow-sm transition hover:bg-indigo-700 disabled:cursor-not-allowed disabled:opacity-50"
        >
          {{
            loading
              ? '正在验证...'
              : retrySeconds > 0
                ? `请等待 ${retrySeconds}s`
                : '登录控制台'
          }}
        </button>
      </form>
    </div>
  </div>
</template>
