<script setup lang="ts">
import { onMounted, ref, computed } from 'vue';
import { useRoute } from 'vue-router';
import { TPanel, useToast } from '@triton/ui';
import type { Organisation } from '@triton/api-client';
import { useApiClient } from '../stores/apiClient';

const api = useApiClient();
const toast = useToast();
const route = useRoute();
const org = ref<Organisation | null>(null);
const id = computed(() => String(route.params.id));

onMounted(async () => {
  try {
    org.value = await api.get().org(id.value);
  } catch (err) {
    toast.error({ title: 'Load failed', description: String(err) });
  }
});
</script>

<template>
  <TPanel
    v-if="org"
    :title="org.name"
  >
    <dl class="kv">
      <dt>ID</dt>
      <dd>{{ org.id }}</dd>
      <dt>Created</dt>
      <dd>{{ org.createdAt }}</dd>
    </dl>
  </TPanel>
  <p v-else>
    Loading&hellip;
  </p>
</template>

<style scoped>
.kv {
  display: grid;
  grid-template-columns: 120px 1fr;
  gap: var(--space-2) var(--space-3);
  font-size: 0.82rem;
}
.kv dt {
  color: var(--text-muted);
  font-size: 0.66rem;
  text-transform: uppercase;
  letter-spacing: 0.1em;
}
.kv dd {
  color: var(--text-primary);
  font-family: var(--font-mono);
  margin: 0;
}
</style>
