<script setup lang="ts">
import { computed } from 'vue';

const props = withDefaults(
  defineProps<{ name: string; initials?: string; size?: number }>(),
  { size: 26, initials: undefined }
);

const text = computed(() => {
  if (props.initials) return props.initials.slice(0, 2).toUpperCase();
  const parts = props.name.trim().split(/\s+/);
  if (parts.length >= 2) {
    const first = parts[0]?.[0] ?? '';
    const second = parts[parts.length - 1]?.[0] ?? '';
    return (first + second).toUpperCase();
  }
  return (parts[0] ?? '').slice(0, 2).toUpperCase();
});
</script>

<template>
  <span
    class="t-avatar"
    :style="{
      width: size + 'px',
      height: size + 'px',
      fontSize: size * 0.4 + 'px'
    }"
    :aria-label="name"
  >{{ text }}</span>
</template>

<style scoped>
.t-avatar {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  border-radius: 50%;
  background: linear-gradient(135deg, var(--accent), #7c3aed);
  color: var(--text-primary);
  font-family: var(--font-display);
  font-weight: 700;
  letter-spacing: -0.02em;
}
</style>
