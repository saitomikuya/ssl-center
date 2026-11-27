<script setup lang="ts">
import { onMounted, onUnmounted } from 'vue'
import { X } from 'lucide-vue-next'

const props = withDefaults(
  defineProps<{
    open: boolean
    title: string
    subtitle?: string
    maxWidth?: 'sm' | 'md' | 'lg' | 'xl' | '2xl' | '4xl' | '5xl'
  }>(),
  {
    maxWidth: 'lg',
  },
)

const emit = defineEmits<{
  close: []
}>()

const widthClass: Record<string, string> = {
  sm: 'max-w-sm',
  md: 'max-w-md',
  lg: 'max-w-lg',
  xl: 'max-w-xl',
  '2xl': 'max-w-2xl',
  '4xl': 'max-w-4xl',
  '5xl': 'max-w-5xl',
}

function onKeydown(e: KeyboardEvent) {
  if (e.key === 'Escape' && props.open) {
    emit('close')
  }
}

onMounted(() => window.addEventListener('keydown', onKeydown))
onUnmounted(() => window.removeEventListener('keydown', onKeydown))
</script>

<template>
  <Teleport to="body">
    <div
      v-if="open"
      class="fixed inset-0 z-50 flex items-center justify-center overflow-y-auto bg-slate-900/50 p-4 backdrop-blur-[1px]"
      @mousedown.self="emit('close')"
    >
      <div
        class="relative flex max-h-[90vh] w-full flex-col overflow-hidden rounded-xl border border-slate-200 bg-white shadow-2xl"
        :class="widthClass[maxWidth]"
      >
        <div class="flex items-start justify-between border-b border-slate-200 px-6 py-4">
          <div>
            <h3 class="text-base font-semibold text-slate-900">{{ title }}</h3>
            <p v-if="subtitle" class="mt-0.5 text-xs text-slate-500">{{ subtitle }}</p>
          </div>
          <button
            type="button"
            class="rounded-lg p-1.5 text-slate-400 transition hover:bg-slate-100 hover:text-slate-600"
            @click="emit('close')"
          >
            <X class="h-4 w-4" />
          </button>
        </div>

        <div class="custom-scrollbar flex-1 overflow-y-auto px-6 py-5">
          <slot />
        </div>

        <div
          v-if="$slots.footer"
          class="flex items-center justify-end gap-3 border-t border-slate-200 bg-slate-50 px-6 py-3.5"
        >
          <slot name="footer" />
        </div>
      </div>
    </div>
  </Teleport>
</template>
