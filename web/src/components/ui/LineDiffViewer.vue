<script setup lang="ts">
import { computed } from 'vue'
import { computeLineDiff } from '@/utils/format'

const props = withDefaults(
  defineProps<{
    oldText: string
    newText: string
    oldLabel?: string
    newLabel?: string
  }>(),
  {
    oldLabel: '原版本',
    newLabel: '新版本',
  },
)

const diffLines = computed(() => computeLineDiff(props.oldText, props.newText))

const stats = computed(() => {
  let added = 0
  let removed = 0
  for (const l of diffLines.value) {
    if (l.type === 'add') added++
    else if (l.type === 'del') removed++
  }
  return { added, removed }
})
</script>

<template>
  <div class="overflow-hidden rounded-lg border border-slate-200 bg-white">
    <div class="flex items-center justify-between border-b border-slate-200 bg-slate-50 px-3.5 py-2 text-xs">
      <div class="flex items-center gap-3">
        <span class="font-medium text-rose-700">- {{ oldLabel }}</span>
        <span class="text-slate-400">vs</span>
        <span class="font-medium text-emerald-700">+ {{ newLabel }}</span>
      </div>
      <div class="flex items-center gap-2 font-mono tabular-nums">
        <span class="text-emerald-700">+{{ stats.added }}</span>
        <span class="text-rose-700">-{{ stats.removed }}</span>
      </div>
    </div>

    <div class="custom-scrollbar max-h-[380px] overflow-auto bg-slate-950 font-mono text-xs leading-5">
      <div
        v-for="(line, idx) in diffLines"
        :key="idx"
        class="flex min-w-max px-2 py-0.5"
        :class="{
          'bg-emerald-950/60 text-emerald-200': line.type === 'add',
          'bg-rose-950/60 text-rose-200': line.type === 'del',
          'text-slate-300': line.type === 'same',
        }"
      >
        <span class="w-10 shrink-0 select-none pr-2 text-right text-slate-500 tabular-nums">
          {{ line.oldLine ?? '' }}
        </span>
        <span class="w-10 shrink-0 select-none pr-2 text-right text-slate-500 tabular-nums">
          {{ line.newLine ?? '' }}
        </span>
        <span class="w-5 shrink-0 select-none text-center font-bold">
          {{ line.type === 'add' ? '+' : line.type === 'del' ? '-' : ' ' }}
        </span>
        <span class="whitespace-pre pr-4">{{ line.text }}</span>
      </div>
    </div>
  </div>
</template>
