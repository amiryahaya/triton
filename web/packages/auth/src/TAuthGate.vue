<script setup lang="ts">
import { computed } from 'vue';
import { useAdminKey } from './adminKey';
import { useJwt } from './jwt';
import TAdminKeyPrompt from './TAdminKeyPrompt.vue';
import TLoginPrompt from './TLoginPrompt.vue';

const props = withDefaults(
  defineProps<{
    type: 'adminKey' | 'jwt';
    title?: string;
    subtitle?: string;
    error?: string;
    busy?: boolean;
  }>(),
  { title: undefined, subtitle: undefined, error: '', busy: false }
);

const emit = defineEmits<{
  login: [creds: { email: string; password: string }];
}>();

const admin = useAdminKey();
const jwt = useJwt();

const authed = computed(() => {
  if (props.type === 'adminKey') return Boolean(admin.key.value);
  // jwt mode — token must exist and not be expired.
  return Boolean(jwt.token.value) && !jwt.isExpired.value;
});

function onAdminSubmit(k: string) {
  admin.setKey(k);
}

function onLoginSubmit(creds: { email: string; password: string }) {
  emit('login', creds);
}
</script>

<template>
  <template v-if="authed">
    <slot />
  </template>
  <template v-else-if="props.type === 'adminKey'">
    <TAdminKeyPrompt @submit="onAdminSubmit" />
  </template>
  <template v-else>
    <TLoginPrompt
      :title="props.title"
      :subtitle="props.subtitle"
      :error="props.error"
      :busy="props.busy"
      @submit="onLoginSubmit"
    />
  </template>
</template>
