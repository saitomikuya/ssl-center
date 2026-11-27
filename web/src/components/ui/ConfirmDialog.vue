<script setup lang="ts">
import ModalDialog from './ModalDialog.vue'
import { AlertTriangle } from 'lucide-vue-next'

withDefaults(
  defineProps<{
    open: boolean
    title: string
    message: string
    confirmText?: string
    cancelText?: string
    danger?: boolean
    loading?: boolean
  }>(),
  {
    confirmText: '确认',
    cancelText: '取消',
    danger: false,
    loading: false,
  },
)

const emit = defineEmits<{
  confirm: []
  cancel: []
}>()
</script>

<template>
  <ModalDialog :open="open" :title="title" max-width="md" @close="emit('cancel')">
    <div class="flex items-start gap-3.5">
      <div
        class="flex h-10 w-10 shrink-0 items-center justify-center rounded-full"
        :class="danger ? 'bg-rose-100 text-rose-600' : 'bg-amber-100 text-amber-600'"
      >
        <AlertTriangle class="h-5 w-5" />
      </div>
      <p class="pt-1 text-sm leading-relaxed text-slate-600 whitespace-pre-line">{{ message }}</p>
    </div>

    <template #footer>
      <button
        type="button"
        class="rounded-lg border border-slate-300 bg-white px-4 py-2 text-sm font-medium text-slate-700 transition hover:bg-slate-50"
        :disabled="loading"
        @click="emit('cancel')"
      >
        {{ cancelText }}
      </button>
      <button
        type="button"
        class="rounded-lg px-4 py-2 text-sm font-medium text-white shadow-sm transition disabled:opacity-50"
        :class="
          danger
            ? 'bg-rose-600 hover:bg-rose-700'
            : 'bg-indigo-600 hover:bg-indigo-700'
        "
        :disabled="loading"
        @click="emit('confirm')"
      >
        {{ loading ? '处理中...' : confirmText }}
      </button>
    </template>
  </ModalDialog>
</template>
