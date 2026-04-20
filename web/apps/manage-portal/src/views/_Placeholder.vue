<script setup lang="ts">
import { useRoute } from 'vue-router';
const route = useRoute();
</script>
<template>
  <div style="padding: 2rem">
    <h2>{{ String(route.name ?? 'unknown') }}</h2>
    <p>{{ route.fullPath }}</p>
  </div>
</template>
