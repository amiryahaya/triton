<script setup lang="ts">
defineProps<{
  label: string;
  required?: boolean;
  error?: string;
  hint?: string;
}>();
</script>

<template>
  <div class="t-field">
    <label class="t-field-label">
      {{ label }}<span
        v-if="required"
        class="t-req"
      >*</span>
    </label>
    <slot />
    <span
      v-if="error"
      class="t-field-error"
    >{{ error }}</span>
    <span
      v-else-if="hint"
      class="t-field-hint"
    >{{ hint }}</span>
  </div>
</template>

<style scoped>
.t-field { display: flex; flex-direction: column; gap: var(--space-1); }
.t-field-label {
  font-size: 0.72rem;
  color: var(--text-muted);
  font-weight: 500;
  font-family: var(--font-body);
}
.t-req { color: var(--unsafe); margin-left: 2px; }
.t-field-hint  { font-size: 0.68rem; color: var(--text-muted); }
.t-field-error { font-size: 0.68rem; color: var(--unsafe); }
</style>
