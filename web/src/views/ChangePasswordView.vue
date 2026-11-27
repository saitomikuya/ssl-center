<script setup lang="ts">
import { ref } from 'vue'
import { useRouter } from 'vue-router'
import { AlertTriangle, KeyRound } from 'lucide-vue-next'
import { changePassword, getMe } from '@/api/auth'
import { ApiError } from '@/api/client'
import { applyAuthMe, authState } from '@/stores/auth'
import { showToast } from '@/stores/toast'

const router = useRouter()

const currentPassword = ref('')
const newPassword = ref('')
const confirmPassword = ref('')
const loading = ref(false)
const errorMsg = ref('')

async function handleSubmit() {
  errorMsg.value = ''
  if (!currentPassword.value || !newPassword.value) {
    errorMsg.value = '请填写当前密码和新密码'
    return
  }
  if (newPassword.value.length < 8) {
    errorMsg.value = '新密码长度不能少于 8 位'
    return
  }
  if (newPassword.value === currentPassword.value) {
    errorMsg.value = '新密码不能与当前密码相同'
    return
  }
  if (newPassword.value !== confirmPassword.value) {
    errorMsg.value = '两次输入的新密码不一致'
    return
  }

  loading.value = true
  try {
    await changePassword({
      current_password: currentPassword.value,
      new_password: newPassword.value,
    })
    const me = await getMe()
    applyAuthMe(me)
    showToast('success', '管理员密码已更新')
    await router.replace('/')
  } catch (err) {
    if (err instanceof ApiError) {
      errorMsg.value = err.status === 401 ? '当前密码不正确' : err.message
    } else {
      errorMsg.value = '修改密码失败，请重试'
    }
  } finally {
    loading.value = false
  }
}
</script>

<template>
  <div class="mx-auto max-w-lg py-6">
    <div class="rounded-2xl border border-slate-200 bg-white p-6 shadow-sm sm:p-8">
      <div class="mb-6 flex items-center gap-3">
        <div class="flex h-10 w-10 items-center justify-center rounded-xl bg-indigo-50 text-indigo-600">
          <KeyRound class="h-5 w-5" />
        </div>
        <div>
          <h1 class="text-lg font-bold text-slate-900">修改管理员密码</h1>
          <p class="text-xs text-slate-500">密码修改后将自动注销其他已登录会话</p>
        </div>
      </div>

      <div
        v-if="authState.mustChangePassword"
        class="mb-6 flex items-start gap-3 rounded-xl border border-amber-200 bg-amber-50 p-4 text-sm text-amber-800"
      >
        <AlertTriangle class="mt-0.5 h-5 w-5 shrink-0 text-amber-600" />
        <div>
          <div class="font-semibold">首次登录安全提示</div>
          <p class="mt-0.5 text-xs leading-relaxed text-amber-700">
            系统检测到当前仍在使用初始管理员密码。为保障证书与凭据安全，必须先修改密码后方可访问其他功能页面。
          </p>
        </div>
      </div>

      <form class="space-y-4" @submit.prevent="handleSubmit">
        <div>
          <label class="mb-1.5 block text-sm font-medium text-slate-700">当前密码</label>
          <input
            v-model="currentPassword"
            type="password"
            autocomplete="current-password"
            placeholder="请输入当前密码"
            class="block w-full rounded-lg border border-slate-300 px-3.5 py-2 text-sm focus:border-indigo-500 focus:outline-none focus:ring-2 focus:ring-indigo-500/20"
          />
        </div>

        <div>
          <label class="mb-1.5 block text-sm font-medium text-slate-700">新密码（至少 8 位）</label>
          <input
            v-model="newPassword"
            type="password"
            autocomplete="new-password"
            placeholder="请输入至少 8 位新密码"
            class="block w-full rounded-lg border border-slate-300 px-3.5 py-2 text-sm focus:border-indigo-500 focus:outline-none focus:ring-2 focus:ring-indigo-500/20"
          />
        </div>

        <div>
          <label class="mb-1.5 block text-sm font-medium text-slate-700">确认新密码</label>
          <input
            v-model="confirmPassword"
            type="password"
            autocomplete="new-password"
            placeholder="请再次输入新密码"
            class="block w-full rounded-lg border border-slate-300 px-3.5 py-2 text-sm focus:border-indigo-500 focus:outline-none focus:ring-2 focus:ring-indigo-500/20"
          />
        </div>

        <div
          v-if="errorMsg"
          class="rounded-lg border border-rose-200 bg-rose-50 px-3.5 py-2 text-xs font-medium text-rose-700"
        >
          {{ errorMsg }}
        </div>

        <div class="flex items-center justify-end gap-3 pt-2">
          <router-link
            v-if="!authState.mustChangePassword"
            to="/"
            class="rounded-lg border border-slate-300 bg-white px-4 py-2 text-sm font-medium text-slate-700 hover:bg-slate-50"
          >
            返回概览
          </router-link>
          <button
            type="submit"
            :disabled="loading"
            class="rounded-lg bg-indigo-600 px-5 py-2 text-sm font-semibold text-white shadow-sm hover:bg-indigo-700 disabled:opacity-50"
          >
            {{ loading ? '保存中...' : '保存新密码' }}
          </button>
        </div>
      </form>
    </div>
  </div>
</template>
