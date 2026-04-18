import { reactive } from 'vue';

export type ToastKind = 'success' | 'warn' | 'error' | 'info';

export interface ToastInput {
  title: string;
  description?: string;
  timeout?: number;
}

export interface ToastEntry extends ToastInput {
  id: number;
  kind: ToastKind;
}

const toasts = reactive<ToastEntry[]>([]);
let nextId = 1;

function push(kind: ToastKind, t: ToastInput): number {
  const id = nextId++;
  const entry: ToastEntry = { id, kind, ...t };
  toasts.push(entry);
  const timeout = t.timeout ?? 5000;
  if (timeout > 0) {
    setTimeout(() => dismiss(id), timeout);
  }
  return id;
}

function dismiss(id: number) {
  const i = toasts.findIndex((t) => t.id === id);
  if (i >= 0) toasts.splice(i, 1);
}

export function useToast() {
  return {
    success: (t: ToastInput) => push('success', t),
    warn:    (t: ToastInput) => push('warn', t),
    error:   (t: ToastInput) => push('error', t),
    info:    (t: ToastInput) => push('info', t),
    dismiss,
  };
}

/** @internal */
export function __resetToastsForTest(): void {
  toasts.splice(0, toasts.length);
  nextId = 1;
}

/** Exported for TToastHost only. */
export const __toastState = toasts;
