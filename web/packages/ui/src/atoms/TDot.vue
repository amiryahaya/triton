<script setup lang="ts">
defineProps<{ color?: string }>();
</script>

<template>
  <span
    class="t-dot"
    :style="color ? { background: color } : undefined"
  />
</template>

<style scoped>
.t-dot {
  display: inline-block;
  width: 5px;
  height: 5px;
  border-radius: 50%;
  background: currentColor;
}
</style>
