<script setup lang="ts">
import { onMounted, ref } from 'vue';
import { TStatCard, useToast } from '@triton/ui';
import type { DashboardStats } from '@triton/api-client';
import { useApiClient } from '../stores/apiClient';

const api = useApiClient();
const toast = useToast();
const stats = ref<DashboardStats | null>(null);

onMounted(async () => {
  try {
    stats.value = await api.get().dashboard();
  } catch (err) {
    toast.error({
      title: 'Could not load dashboard',
      description: String(err),
    });
  }
});
</script>

<template>
  <div class="dash">
    <h1 class="page-h1">Fleet health</h1>

    <div
      v-if="stats"
      class="stat-grid"
    >
      <TStatCard
        label="Total orgs"
        :value="stats.totalOrgs"
        accent="var(--accent)"
      />
      <TStatCard
        label="Total licences"
        :value="stats.totalLicenses"
        accent="var(--accent)"
      />
      <TStatCard
        label="Active licences"
        :value="stats.activeLicenses"
        accent="var(--safe)"
      />
      <TStatCard
        label="Revoked licences"
        :value="stats.revokedLicenses"
        accent="var(--unsafe)"
      />
      <TStatCard
        label="Expired licences"
        :value="stats.expiredLicenses"
        accent="var(--warn)"
      />
      <TStatCard
        label="Total activations"
        :value="stats.totalActivations"
        accent="var(--violet)"
      />
      <TStatCard
        label="Active seats"
        :value="stats.activeSeats"
        accent="var(--violet)"
      />
    </div>

    <div
      v-else
      class="placeholder"
    >
      Loading…
    </div>
  </div>
</template>

<style scoped>
.page-h1 {
  font-family: var(--font-display);
  font-size: 1.55rem;
  letter-spacing: -0.03em;
  font-weight: 600;
  margin: 0 0 var(--space-4);
  color: var(--text-primary);
}
.stat-grid {
  display: grid;
  grid-template-columns: repeat(4, 1fr);
  gap: var(--space-2);
}
.placeholder {
  padding: var(--space-6);
  text-align: center;
  color: var(--text-muted);
}
.dash {
  display: flex;
  flex-direction: column;
  gap: var(--space-3);
}
</style>
