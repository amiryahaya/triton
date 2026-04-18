<script setup lang="ts">
import { ref, onMounted, onUnmounted } from 'vue';
import TAvatar from '../atoms/TAvatar.vue';

withDefaults(
  defineProps<{ name: string; role?: string; org?: string }>(),
  { role: undefined, org: undefined }
);

const emit = defineEmits<{ 'sign-out': [] }>();

const open = ref(false);
const root = ref<HTMLElement | null>(null);
// Separate ref for the Teleport'd popover — root.contains() returns
// false for teleported descendants.
const popover = ref<HTMLElement | null>(null);

function toggle() { open.value = !open.value; }
function close(ev: MouseEvent) {
  const t = ev.target as Node;
  if (!root.value?.contains(t) && !popover.value?.contains(t)) {
    open.value = false;
  }
}
onMounted(() => document.addEventListener('click', close));
onUnmounted(() => document.removeEventListener('click', close));
</script>

<template>
  <div
    ref="root"
    class="t-user-menu"
  >
    <button
      type="button"
      class="t-user-trigger"
      :aria-label="`Account menu for ${name}`"
      :aria-expanded="open"
      aria-haspopup="menu"
      @click="toggle"
    >
      <TAvatar :name="name" />
    </button>
    <Teleport to="body">
      <div
        v-if="open"
        ref="popover"
        class="t-user-pop"
        role="menu"
      >
        <div class="t-user-who">
          <b>{{ name }}</b>
          <span v-if="role">{{ role }}</span>
          <span
            v-if="org"
            class="t-user-org"
          >{{ org }}</span>
        </div>
        <hr class="t-user-sep">
        <button
          type="button"
          class="t-user-item"
          @click="emit('sign-out')"
        >
          Sign out
        </button>
      </div>
    </Teleport>
  </div>
</template>

<style scoped>
.t-user-trigger {
  background: none;
  border: none;
  cursor: pointer;
  padding: 0;
  border-radius: 50%;
}

.t-user-trigger:focus-visible {
  outline: 2px solid var(--accent-strong);
  outline-offset: 2px;
}

.t-user-pop {
  position: fixed;
  top: calc(var(--topbar-h) + 4px);
  right: var(--space-3);
  z-index: var(--z-modal);
  background: var(--bg-surface);
  border: 1px solid var(--border-strong);
  border-radius: var(--radius);
  min-width: 200px;
  box-shadow: var(--shadow-lg);
  padding: var(--space-1);
}

.t-user-who {
  padding: var(--space-2) var(--space-3);
  display: flex;
  flex-direction: column;
  gap: 2px;
  font-size: 0.75rem;
  color: var(--text-primary);
}

.t-user-who b {
  font-family: var(--font-display);
  font-weight: 600;
  letter-spacing: -0.01em;
}

.t-user-who span {
  color: var(--text-muted);
  font-size: 0.68rem;
}

.t-user-sep {
  border: none;
  border-top: 1px solid var(--border);
  margin: var(--space-1) 0;
}

.t-user-item {
  background: none;
  border: none;
  width: 100%;
  padding: var(--space-2) var(--space-3);
  text-align: left;
  color: var(--text-primary);
  font-size: 0.76rem;
  border-radius: var(--radius-sm);
  cursor: pointer;
}

.t-user-item:hover {
  background: var(--bg-hover);
}

.t-user-item:focus-visible {
  outline: 2px solid var(--accent-strong);
  outline-offset: -2px;
}
</style>
