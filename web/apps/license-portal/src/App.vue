<script setup lang="ts">
import { useTheme } from '@triton/ui';

// Initialise theme once at app mount.
useTheme();
</script>

<template>
  <router-view />
</template>
