<script setup lang="ts"></script>

<template>
  <kbd class="t-kbd"><slot /></kbd>
</template>

<style scoped>
.t-kbd {
  display: inline-block;
  font-family: var(--font-mono);
  font-size: 0.62rem;
  color: var(--text-muted);
  background: var(--bg-base);
  border: 1px solid var(--border);
  border-radius: 3px;
  padding: 0 var(--space-1);
  line-height: 1.4;
}
</style>
