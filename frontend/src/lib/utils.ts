import { clsx, type ClassValue } from "clsx"
import { twMerge } from "tailwind-merge"

export function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs))
}

export function formatSize(bytes: number): string {
  if (bytes < 1024) {
    return `${bytes}B`
  }
  const kb = bytes / 1024
  if (kb < 1024) {
    return `${kb.toFixed(0)}K`
  }
  const mb = kb / 1024
  if (mb < 1024) {
    return `${mb.toFixed(1)}M`
  }
  const gb = mb / 1024
  return `${gb.toFixed(1)}G`
}

export function truncatePath(path: string, maxLen: number): string {
  if (path.length <= maxLen) {
    return path
  }
  const fileName = path.split(/[/\\]/).pop() || ''
  if (fileName.length < maxLen - 10) {
    const prefix = path.substring(0, maxLen - fileName.length - 4)
    return prefix + '...' + fileName
  }
  return '...' + path.substring(path.length - maxLen + 3)
}
