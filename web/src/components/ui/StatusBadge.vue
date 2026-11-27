<script setup lang="ts">
import { computed } from 'vue'

const props = defineProps<{
  status: string
  label?: string
}>()

const config = computed(() => {
  const s = (props.status || '').toLowerCase()
  switch (s) {
    case 'valid':
    case 'active':
    case 'success':
    case 'running':
      return {
        cls: 'bg-emerald-50 text-emerald-700 ring-emerald-600/20',
        dot: 'bg-emerald-500',
        text:
          s === 'valid'
            ? '有效'
            : s === 'active'
              ? '正常'
              : s === 'success'
                ? '成功'
                : '运行中',
      }
    case 'expiring':
    case 'warn':
    case 'warning':
      return {
        cls: 'bg-amber-50 text-amber-700 ring-amber-600/20',
        dot: 'bg-amber-500',
        text: s === 'expiring' ? '即将过期' : '警告',
      }
    case 'expired':
    case 'error':
    case 'failed':
    case 'stopped':
      return {
        cls: 'bg-rose-50 text-rose-700 ring-rose-600/20',
        dot: 'bg-rose-500',
        text:
          s === 'expired'
            ? '已过期'
            : s === 'stopped'
              ? '已停止'
              : s === 'failed'
                ? '失败'
                : '异常',
      }
    case 'issuing':
      return {
        cls: 'bg-indigo-50 text-indigo-700 ring-indigo-600/20',
        dot: 'bg-indigo-500 animate-pulse',
        text: '签发中',
      }
    case 'pending':
    case 'unknown':
    case 'info':
    default:
      return {
        cls: 'bg-slate-100 text-slate-700 ring-slate-500/20',
        dot: 'bg-slate-400',
        text:
          s === 'pending'
            ? '待处理'
            : s === 'unknown'
              ? '未知'
              : s === 'info'
                ? '信息'
                : props.status || '未知',
      }
  }
})
</script>

<template>
  <span
    class="inline-flex items-center gap-1.5 rounded-full px-2.5 py-0.5 text-xs font-medium ring-1 ring-inset"
    :class="config.cls"
  >
    <span class="h-1.5 w-1.5 rounded-full" :class="config.dot" />
    <span>{{ label || config.text }}</span>
  </span>
</template>
