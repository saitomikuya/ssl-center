export function formatDateTime(iso?: string | null): string {
  if (!iso) return '—'
  const d = new Date(iso)
  if (Number.isNaN(d.getTime())) return iso
  const pad = (n: number) => String(n).padStart(2, '0')
  return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())} ${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}`
}

export function formatShortDate(iso?: string | null): string {
  if (!iso) return '—'
  const d = new Date(iso)
  if (Number.isNaN(d.getTime())) return iso
  const pad = (n: number) => String(n).padStart(2, '0')
  return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}`
}

export function formatRelativeTime(iso?: string | null): string {
  if (!iso) return '—'
  const d = new Date(iso)
  if (Number.isNaN(d.getTime())) return iso
  const diffSec = Math.floor((Date.now() - d.getTime()) / 1000)
  if (diffSec < 60) return '刚刚'
  if (diffSec < 3600) return `${Math.floor(diffSec / 60)} 分钟前`
  if (diffSec < 86400) return `${Math.floor(diffSec / 3600)} 小时前`
  return `${Math.floor(diffSec / 86400)} 天前`
}

export async function copyToClipboard(text: string): Promise<boolean> {
  if (navigator.clipboard && window.isSecureContext) {
    try {
      await navigator.clipboard.writeText(text)
      return true
    } catch {
      // Fallback below
    }
  }
  const textarea = document.createElement('textarea')
  textarea.value = text
  textarea.style.position = 'fixed'
  textarea.style.left = '-9999px'
  document.body.appendChild(textarea)
  textarea.focus()
  textarea.select()
  let ok = false
  try {
    ok = document.execCommand('copy')
  } catch {
    ok = false
  }
  document.body.removeChild(textarea)
  return ok
}

export interface DiffLine {
  type: 'same' | 'add' | 'del'
  oldLine?: number
  newLine?: number
  text: string
}

/**
 * Computes a clean line-by-line LCS diff between oldText (left/remote/snapshot) and newText (right/local/current).
 */
export function computeLineDiff(oldText: string, newText: string): DiffLine[] {
  const a = oldText.replace(/\r\n/g, '\n').split('\n')
  const b = newText.replace(/\r\n/g, '\n').split('\n')
  const m = a.length
  const n = b.length

  // Guard for very large files: fallback to simple line-by-line prefix/suffix if m*n > 250000
  if (m * n > 250000) {
    const out: DiffLine[] = []
    const maxLen = Math.max(m, n)
    for (let i = 0; i < maxLen; i++) {
      if (i < m && i < n && a[i] === b[i]) {
        out.push({ type: 'same', oldLine: i + 1, newLine: i + 1, text: a[i] })
      } else {
        if (i < m) out.push({ type: 'del', oldLine: i + 1, text: a[i] })
        if (i < n) out.push({ type: 'add', newLine: i + 1, text: b[i] })
      }
    }
    return out
  }

  const dp: Int32Array[] = Array.from({ length: m + 1 }, () => new Int32Array(n + 1))
  for (let i = m - 1; i >= 0; i--) {
    for (let j = n - 1; j >= 0; j--) {
      if (a[i] === b[j]) {
        dp[i][j] = dp[i + 1][j + 1] + 1
      } else {
        dp[i][j] = dp[i + 1][j] >= dp[i][j + 1] ? dp[i + 1][j] : dp[i][j + 1]
      }
    }
  }

  const result: DiffLine[] = []
  let i = 0
  let j = 0
  while (i < m && j < n) {
    if (a[i] === b[j]) {
      result.push({ type: 'same', oldLine: i + 1, newLine: j + 1, text: a[i] })
      i++
      j++
    } else if (dp[i + 1][j] >= dp[i][j + 1]) {
      result.push({ type: 'del', oldLine: i + 1, text: a[i] })
      i++
    } else {
      result.push({ type: 'add', newLine: j + 1, text: b[j] })
      j++
    }
  }
  while (i < m) {
    result.push({ type: 'del', oldLine: i + 1, text: a[i] })
    i++
  }
  while (j < n) {
    result.push({ type: 'add', newLine: j + 1, text: b[j] })
    j++
  }
  return result
}

export function truncateFingerprint(fp?: string | null, len = 16): string {
  if (!fp) return '—'
  if (fp.length <= len * 2) return fp
  return `${fp.slice(0, len)}...${fp.slice(-len)}`
}

export function certSubdirName(domain: string, certId: number): string {
  let d = (domain || '').trim()
  if (d.startsWith('*.')) {
    d = d.slice(2)
  }
  const sanitized = d.replace(/[^a-zA-Z0-9._-]/g, '').replace(/^[._-]+|[._-]+$/g, '')
  return sanitized || `cert_${certId}`
}
