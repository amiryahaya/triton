<script setup lang="ts">
import { ref } from 'vue';
import { TButton, TInput, TFormField } from '@triton/ui';

withDefaults(
  defineProps<{
    title?: string;
    subtitle?: string;
    error?: string;
    busy?: boolean;
  }>(),
  {
    title: 'Report Server',
    subtitle: 'Sign in to continue.',
    error: '',
    busy: false,
  }
);

const emit = defineEmits<{ submit: [creds: { email: string; password: string }] }>();

const email = ref('');
const password = ref('');

function onSubmit(ev: Event) {
  ev.preventDefault();
  const e = email.value.trim();
  if (!e || !password.value) return;
  emit('submit', { email: e, password: password.value });
}
</script>

<template>
  <div class="t-login-prompt">
    <form
      class="t-login-card"
      novalidate
      @submit="onSubmit"
    >
      <h1 class="t-login-title">
        {{ title }}
      </h1>
      <p class="t-login-sub">
        {{ subtitle }}
      </p>
      <TFormField
        label="Email"
        required
      >
        <TInput
          v-model="email"
          type="email"
          autocomplete="email"
          placeholder="you@example.com"
        />
      </TFormField>
      <TFormField
        label="Password"
        required
      >
        <TInput
          v-model="password"
          type="password"
          autocomplete="current-password"
        />
      </TFormField>
      <p
        v-if="error"
        class="t-login-error"
        role="alert"
      >
        {{ error }}
      </p>
      <TButton
        type="submit"
        variant="primary"
        :disabled="busy || !email.trim() || !password"
      >
        {{ busy ? 'Signing in…' : 'Sign in' }}
      </TButton>
    </form>
  </div>
</template>

<style scoped>
.t-login-prompt {
  min-height: 100vh;
  display: flex;
  align-items: center;
  justify-content: center;
  background: var(--bg-base);
}
.t-login-card {
  background: var(--bg-surface);
  border: 1px solid var(--border);
  border-radius: var(--radius-lg);
  padding: var(--space-8) var(--space-8);
  width: min(360px, 92vw);
  display: flex;
  flex-direction: column;
  gap: var(--space-3);
  box-shadow: var(--shadow-lg);
}
.t-login-title {
  font-family: var(--font-display);
  font-size: 1.6rem;
  font-weight: 600;
  letter-spacing: -0.02em;
  color: var(--text-primary);
  margin: 0;
}
.t-login-sub {
  color: var(--text-muted);
  font-size: 0.82rem;
  margin: 0;
}
.t-login-error {
  color: var(--unsafe);
  font-size: 0.82rem;
  margin: 0;
}
</style>
