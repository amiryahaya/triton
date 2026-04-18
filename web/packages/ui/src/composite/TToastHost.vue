<script setup lang="ts">
import { __toastState, useToast } from '../composables/useToast';

const { dismiss } = useToast();
const toasts = __toastState;

const icon = {
  success: '✓',
  warn: '!',
  error: '×',
  info: 'i',
} as const;
</script>

<template>
  <Teleport to="body">
    <div
      class="t-toast-host"
      aria-live="polite"
    >
      <div
        v-for="t in toasts"
        :key="t.id"
        class="t-toast"
        :class="`t-toast--${t.kind}`"
      >
        <span class="t-toast-ico">{{ icon[t.kind] }}</span>
        <div class="t-toast-body">
          <b>{{ t.title }}</b>
          <span v-if="t.description">{{ t.description }}</span>
        </div>
        <button
          type="button"
          class="t-toast-close"
          aria-label="Dismiss"
          @click="dismiss(t.id)"
        >
          ×
        </button>
      </div>
    </div>
  </Teleport>
</template>

<style scoped>
.t-toast-host {
  position: fixed;
  bottom: var(--space-5);
  right: var(--space-5);
  z-index: var(--z-toast);
  display: flex;
  flex-direction: column;
  gap: var(--space-2);
  max-width: 360px;
}
.t-toast {
  display: flex;
  align-items: flex-start;
  gap: var(--space-2);
  padding: var(--space-2) var(--space-3);
  border-radius: var(--radius);
  border: 1px solid;
  font-size: 0.78rem;
  background: var(--bg-surface);
  box-shadow: var(--shadow);
  animation: toastIn var(--motion-enter) var(--ease-out);
}
@keyframes toastIn {
  from { opacity: 0; transform: translateX(20px); }
  to   { opacity: 1; transform: translateX(0); }
}
.t-toast-ico {
  width: 18px;
  height: 18px;
  border-radius: 50%;
  display: flex;
  align-items: center;
  justify-content: center;
  font-size: 0.68rem;
  font-weight: 700;
  flex-shrink: 0;
  color: var(--bg-base);
}
.t-toast-body {
  flex: 1;
  display: flex;
  flex-direction: column;
  gap: 1px;
  color: var(--text-primary);
}
.t-toast-close {
  background: none;
  border: none;
  color: var(--text-muted);
  font-size: 1rem;
  cursor: pointer;
  padding: 0;
  border-radius: var(--radius-sm);
}
.t-toast-close:focus-visible {
  outline: 2px solid var(--accent-strong);
  outline-offset: 2px;
}

.t-toast--success { border-color: var(--safe); background: var(--safe-muted); }
.t-toast--success .t-toast-ico { background: var(--safe); }
.t-toast--warn { border-color: var(--warn); background: var(--warn-muted); }
.t-toast--warn .t-toast-ico { background: var(--warn); }
.t-toast--error { border-color: var(--unsafe); background: var(--unsafe-muted); }
.t-toast--error .t-toast-ico { background: var(--unsafe); }
.t-toast--info { border-color: var(--accent-strong); background: var(--accent-muted); }
.t-toast--info .t-toast-ico { background: var(--accent-strong); }
</style>
