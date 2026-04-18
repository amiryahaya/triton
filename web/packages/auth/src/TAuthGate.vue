<script setup lang="ts">
import { useAdminKey } from './adminKey';
import TAdminKeyPrompt from './TAdminKeyPrompt.vue';

// type is a switch for future JWT gate; today only adminKey.
defineProps<{ type: 'adminKey' }>();

const admin = useAdminKey();

function onSubmit(k: string) {
  admin.setKey(k);
}
</script>

<template>
  <TAdminKeyPrompt
    v-if="!admin.key.value"
    @submit="onSubmit"
  />
  <slot v-else />
</template>
