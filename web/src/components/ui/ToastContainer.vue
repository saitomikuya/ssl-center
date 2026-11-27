<script setup lang="ts">
import { dismissToast, toastState } from '@/stores/toast'
import { AlertCircle, AlertTriangle, CheckCircle2, Info, X } from 'lucide-vue-next'
</script>

<template>
  <div class="pointer-events-none fixed right-4 top-4 z-[100] flex w-full max-w-sm flex-col gap-2.5">
    <div
      v-for="item in toastState.items"
      :key="item.id"
      class="pointer-events-auto flex items-start gap-3 rounded-xl border bg-white p-3.5 shadow-lg transition-all"
      :class="{
        'border-emerald-200': item.type === 'success',
        'border-rose-200': item.type === 'error',
        'border-amber-200': item.type === 'warning',
        'border-slate-200': item.type === 'info',
      }"
    >
      <CheckCircle2 v-if="item.type === 'success'" class="mt-0.5 h-5 w-5 shrink-0 text-emerald-500" />
      <AlertCircle v-else-if="item.type === 'error'" class="mt-0.5 h-5 w-5 shrink-0 text-rose-500" />
      <AlertTriangle v-else-if="item.type === 'warning'" class="mt-0.5 h-5 w-5 shrink-0 text-amber-500" />
      <Info v-else class="mt-0.5 h-5 w-5 shrink-0 text-indigo-500" />

      <div class="min-w-0 flex-1">
        <p v-if="item.title" class="text-sm font-semibold text-slate-900">{{ item.title }}</p>
        <p class="text-sm text-slate-600 break-words">{{ item.message }}</p>
      </div>

      <button
        type="button"
        class="rounded p-0.5 text-slate-400 hover:bg-slate-100 hover:text-slate-600"
        @click="dismissToast(item.id)"
      >
        <X class="h-4 w-4" />
      </button>
    </div>
  </div>
</template>
