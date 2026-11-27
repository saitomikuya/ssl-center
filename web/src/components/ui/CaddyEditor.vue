<script setup lang="ts">
import { onMounted, onUnmounted, ref, watch } from 'vue'
import { basicSetup } from 'codemirror'
import { EditorView, keymap, Decoration, type DecorationSet } from '@codemirror/view'
import { EditorState, StateEffect, StateField } from '@codemirror/state'
import { StreamLanguage, HighlightStyle, syntaxHighlighting } from '@codemirror/language'
import { tags } from '@lezer/highlight'

const props = withDefaults(
  defineProps<{
    modelValue: string
    errorLine?: number | null
    readonly?: boolean
  }>(),
  {
    errorLine: null,
    readonly: false,
  },
)

const emit = defineEmits<{
  'update:modelValue': [value: string]
  save: []
}>()

const containerRef = ref<HTMLDivElement | null>(null)
let view: EditorView | null = null
let syncingFromProp = false

const CADDY_DIRECTIVES = new Set([
  'tls',
  'reverse_proxy',
  'file_server',
  'root',
  'encode',
  'header',
  'handle',
  'handle_path',
  'route',
  'redir',
  'rewrite',
  'respond',
  'import',
  'log',
  'basicauth',
  'basic_auth',
  'php_fastcgi',
  'try_files',
  'templates',
  'push',
  'request_body',
  'uri',
  'vars',
  'map',
  'abort',
  'error',
  'handle_errors',
  'metrics',
  'bind',
  'protocols',
  'email',
  'acme_ca',
  'admin',
  'auto_https',
  'servers',
  'storage',
])

const caddyLanguage = StreamLanguage.define({
  token(stream) {
    if (stream.eatSpace()) return null

    if (stream.peek() === '#') {
      stream.skipToEnd()
      return 'comment'
    }

    if (stream.peek() === '"') {
      stream.next()
      let escaped = false
      while (!stream.eol()) {
        const ch = stream.next()
        if (escaped) {
          escaped = false
        } else if (ch === '\\') {
          escaped = true
        } else if (ch === '"') {
          break
        }
      }
      return 'string'
    }

    if (stream.peek() === '{') {
      if (stream.match(/^\{[a-zA-Z0-9_.*-]+\}/)) {
        return 'variableName'
      }
      stream.next()
      return 'punctuation'
    }

    if (stream.peek() === '}') {
      stream.next()
      return 'punctuation'
    }

    if (stream.match(/^@[a-zA-Z0-9_-]+/)) {
      return 'labelName'
    }

    if (stream.match(/^\/[^\s{}]*/)) {
      return 'string'
    }

    if (stream.match(/^[0-9]+(ms|s|m|h)?\b/)) {
      return 'number'
    }

    if (stream.match(/^(on|off|true|false)\b/)) {
      return 'atom'
    }

    if (stream.match(/^[^\s{}#"]+/, true)) {
      const word = stream.current()
      if (CADDY_DIRECTIVES.has(word)) {
        return 'keyword'
      }
      if (word.includes('.') || word.startsWith(':') || word.startsWith('http://') || word.startsWith('https://')) {
        return 'typeName'
      }
      return 'propertyName'
    }

    stream.next()
    return null
  },
})

const caddyHighlight = HighlightStyle.define([
  { tag: tags.comment, color: '#64748b', fontStyle: 'italic' },
  { tag: tags.keyword, color: '#4f46e5', fontWeight: '600' },
  { tag: tags.string, color: '#059669' },
  { tag: tags.typeName, color: '#0284c7', fontWeight: '600' },
  { tag: tags.labelName, color: '#d97706', fontWeight: '500' },
  { tag: tags.variableName, color: '#7c3aed' },
  { tag: tags.number, color: '#ea580c' },
  { tag: tags.atom, color: '#0d9488' },
  { tag: tags.propertyName, color: '#1e293b' },
  { tag: tags.punctuation, color: '#475569', fontWeight: '600' },
])

const setErrorLineEffect = StateEffect.define<number | null>()

const errorLineField = StateField.define<DecorationSet>({
  create() {
    return Decoration.none
  },
  update(decorations, tr) {
    decorations = decorations.map(tr.changes)
    for (const effect of tr.effects) {
      if (effect.is(setErrorLineEffect)) {
        const lineNum = effect.value
        if (!lineNum || lineNum < 1 || lineNum > tr.state.doc.lines) {
          return Decoration.none
        }
        const line = tr.state.doc.line(lineNum)
        return Decoration.set([Decoration.line({ class: 'cm-error-line' }).range(line.from)])
      }
    }
    return decorations
  },
  provide: (f) => EditorView.decorations.from(f),
})

const editorTheme = EditorView.theme({
  '&': {
    backgroundColor: '#ffffff',
    color: '#0f172a',
    height: '100%',
  },
  '.cm-gutters': {
    backgroundColor: '#f8fafc',
    color: '#94a3b8',
    borderRight: '1px solid #e2e8f0',
    minWidth: '44px',
  },
  '.cm-activeLineGutter': {
    backgroundColor: '#eef2ff',
    color: '#4f46e5',
    fontWeight: '600',
  },
  '.cm-activeLine': {
    backgroundColor: '#f8fafc',
  },
  '.cm-scroller': {
    overflow: 'auto',
  },
})

function applyErrorLine(lineNum: number | null) {
  if (!view) return
  view.dispatch({
    effects: setErrorLineEffect.of(lineNum),
  })
  if (lineNum && lineNum >= 1 && lineNum <= view.state.doc.lines) {
    const line = view.state.doc.line(lineNum)
    view.dispatch({
      effects: EditorView.scrollIntoView(line.from, { y: 'center' }),
    })
  }
}

function insertSnippet(snippet: string) {
  if (!view) return
  const sel = view.state.selection.main
  const currentLine = view.state.doc.lineAt(sel.from)
  const indentMatch = /^\s*/.exec(currentLine.text)
  const indent = indentMatch ? indentMatch[0] : ''
  const needsNewlineBefore = sel.from > currentLine.from && currentLine.text.trim().length > 0
  const insertText = needsNewlineBefore ? `\n${indent}${snippet}` : snippet
  view.dispatch({
    changes: { from: sel.from, to: sel.to, insert: insertText },
    selection: { anchor: sel.from + insertText.length },
  })
  view.focus()
}

defineExpose({ insertSnippet })

onMounted(() => {
  if (!containerRef.value) return

  const state = EditorState.create({
    doc: props.modelValue,
    extensions: [
      basicSetup,
      caddyLanguage,
      syntaxHighlighting(caddyHighlight),
      editorTheme,
      errorLineField,
      EditorState.readOnly.of(props.readonly),
      keymap.of([
        {
          key: 'Mod-s',
          run: () => {
            emit('save')
            return true
          },
        },
      ]),
      EditorView.updateListener.of((update) => {
        if (update.docChanged && !syncingFromProp) {
          emit('update:modelValue', update.state.doc.toString())
        }
      }),
    ],
  })

  view = new EditorView({
    state,
    parent: containerRef.value,
  })

  if (props.errorLine) {
    applyErrorLine(props.errorLine)
  }
})

watch(
  () => props.modelValue,
  (newVal) => {
    if (!view) return
    const current = view.state.doc.toString()
    if (newVal !== current) {
      syncingFromProp = true
      view.dispatch({
        changes: { from: 0, to: current.length, insert: newVal },
      })
      syncingFromProp = false
    }
  },
)

watch(
  () => props.errorLine,
  (line) => {
    applyErrorLine(line ?? null)
  },
)

onUnmounted(() => {
  view?.destroy()
  view = null
})
</script>

<template>
  <div
    ref="containerRef"
    class="h-full w-full overflow-hidden rounded-lg border border-slate-200 bg-white"
  />
</template>
