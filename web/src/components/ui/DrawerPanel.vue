<script setup lang="ts">
import { onMounted, onUnmounted } from 'vue'
import { X } from 'lucide-vue-next'

const props = withDefaults(
  defineProps<{
    open: boolean
    title: string
    subtitle?: string
    widthClass?: string
  }>(),
  {
    widthClass: 'max-w-3xl',
  },
)

const emit = defineEmits<{
  close: []
}>()

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
      class="fixed inset-0 z-40 flex justify-end bg-slate-900/40 backdrop-blur-[1px]"
      @mousedown.self="emit('close')"
    >
      <div
        class="flex h-full w-full flex-col bg-white shadow-2xl"
        :class="widthClass"
      >
        <div class="flex items-start justify-between border-b border-slate-200 px-6 py-4">
          <div class="min-w-0 pr-4">
            <h2 class="truncate text-lg font-semibold text-slate-900">{{ title }}</h2>
            <p v-if="subtitle" class="mt-0.5 truncate text-xs text-slate-500">{{ subtitle }}</p>
          </div>
          <button
            type="button"
            class="rounded-lg p-1.5 text-slate-400 transition hover:bg-slate-100 hover:text-slate-600"
            @click="emit('close')"
          >
            <X class="h-5 w-5" />
          </button>
        </div>

        <div v-if="$slots.headerExtra" class="border-b border-slate-200 bg-slate-50/70 px-6">
          <slot name="headerExtra" />
        </div>

        <div class="custom-scrollbar flex-1 overflow-y-auto p-6">
          <slot />
        </div>
      </div>
    </div>
  </Teleport>
</template>
