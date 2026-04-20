<script setup lang="ts">
import { ref } from 'vue';

const props = defineProps<{ code: string; label?: string }>();
const copied = ref(false);

async function copy() {
  await navigator.clipboard.writeText(props.code);
  copied.value = true;
  setTimeout(() => {
    copied.value = false;
  }, 1500);
}
</script>
<template>
  <div class="code-block">
    <code>{{ props.code }}</code>
    <button type="button" class="copy" @click="copy">
      {{ copied ? 'Copied' : 'Copy' }}
    </button>
  </div>
</template>
<style scoped>
.code-block {
  display: flex;
  align-items: center;
  gap: var(--space-2);
  padding: var(--space-3);
  background: var(--bg-code, var(--bg-surface));
  border-radius: var(--radius);
  font-family: var(--font-mono);
}
.copy {
  margin-left: auto;
  padding: 2px 8px;
  font-size: 0.75rem;
  border: 1px solid var(--border);
  background: transparent;
  cursor: pointer;
}
</style>
