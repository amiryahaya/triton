<script setup lang="ts">
import { ref, watch, onMounted, onUnmounted } from 'vue';
import { useFocusTrap } from '../composables/useFocusTrap';

const props = withDefaults(
  defineProps<{
    open: boolean;
    title: string;
    width?: string;
  }>(),
  { width: undefined }
);

const emit = defineEmits<{ close: [] }>();

const panel = ref<HTMLElement | null>(null);
useFocusTrap(panel);

function onEsc(ev: KeyboardEvent) {
  if (ev.key === 'Escape' && props.open) emit('close');
}

onMounted(() => document.addEventListener('keydown', onEsc));
onUnmounted(() => document.removeEventListener('keydown', onEsc));

watch(
  () => props.open,
  (o) => {
    document.body.style.overflow = o ? 'hidden' : '';
  }
);
</script>

<template>
  <Teleport to="body">
    <div
      v-if="open"
      class="t-modal-backdrop"
      @click.self="emit('close')"
    >
      <div
        ref="panel"
        class="t-modal"
        role="dialog"
        aria-modal="true"
        :style="{ width: width ?? 'min(480px, 90vw)' }"
      >
        <header class="t-modal-head">
          <h3 class="t-modal-title">
            {{ title }}
          </h3>
          <button
            type="button"
            class="t-modal-close"
            aria-label="Close"
            @click="emit('close')"
          >
            ×
          </button>
        </header>
        <div class="t-modal-body">
          <slot />
        </div>
        <footer
          v-if="$slots.footer"
          class="t-modal-foot"
        >
          <slot name="footer" />
        </footer>
      </div>
    </div>
  </Teleport>
</template>

<style scoped>
.t-modal-backdrop {
  position: fixed;
  inset: 0;
  z-index: var(--z-modal);
  background: rgba(0, 0, 0, 0.6);
  display: flex;
  align-items: center;
  justify-content: center;
  backdrop-filter: blur(2px);
}
.t-modal {
  background: var(--bg-surface);
  border: 1px solid var(--border-strong);
  border-radius: var(--radius);
  box-shadow: var(--shadow-lg);
  max-height: 90vh;
  overflow: hidden;
  display: flex;
  flex-direction: column;
  animation: modalIn var(--motion-modal) var(--ease-out);
}
@keyframes modalIn {
  from { opacity: 0; transform: translateY(10px) scale(0.98); }
  to   { opacity: 1; transform: translateY(0) scale(1); }
}
.t-modal-head {
  padding: var(--space-3) var(--space-4);
  display: flex;
  justify-content: space-between;
  align-items: center;
  border-bottom: 1px solid var(--border);
}
.t-modal-title {
  font-family: var(--font-display);
  font-size: 1.05rem;
  font-weight: 600;
  letter-spacing: -0.01em;
  margin: 0;
  color: var(--text-primary);
}
.t-modal-close {
  background: none;
  border: none;
  color: var(--text-muted);
  font-size: 1.3rem;
  line-height: 1;
  cursor: pointer;
  padding: 0;
  border-radius: var(--radius-sm);
}
.t-modal-close:focus-visible {
  outline: 2px solid var(--accent-strong);
  outline-offset: 2px;
}
.t-modal-body {
  padding: var(--space-3) var(--space-4);
  overflow: auto;
  color: var(--text-secondary);
  font-size: 0.85rem;
}
.t-modal-foot {
  padding: var(--space-2) var(--space-4);
  border-top: 1px solid var(--border);
  display: flex;
  gap: var(--space-2);
  justify-content: flex-end;
}
</style>
