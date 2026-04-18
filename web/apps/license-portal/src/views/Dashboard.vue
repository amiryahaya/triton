<script setup lang="ts">
import { onMounted, ref } from 'vue';
import { TStatCard, TPanel, TLineChart, useToast } from '@triton/ui';
import type { DashboardStats } from '@triton/api-client';
import { useApiClient } from '../stores/apiClient';

const api = useApiClient();
const toast = useToast();
const stats = ref<DashboardStats | null>(null);

onMounted(async () => {
  try {
    stats.value = await api.get().dashboard();
  } catch (err) {
    toast.error({ title: 'Could not load dashboard', description: String(err) });
  }
});
</script>

<template>
  <div class="dash">
    <h1 class="page-h1">Fleet health</h1>

    <div
      v-if="stats"
      class="stat-row"
    >
      <TStatCard
        label="Organisations"
        :value="stats.orgs"
        accent="var(--accent)"
      />
      <TStatCard
        label="Seats used"
        :value="`${stats.seatsUsed} / ${stats.seatsTotal}`"
        accent="var(--violet)"
      />
      <TStatCard
        label="Expiring 30d"
        :value="stats.expiringIn30d"
        accent="var(--warn)"
      />
    </div>

    <TPanel
      title="Licence activations"
      subtitle="· last 12 weeks"
    >
      <TLineChart
        :labels="['W1','W2','W3','W4','W5','W6','W7','W8','W9','W10','W11','W12']"
        :values="[3,5,7,6,9,11,14,16,19,22,25,28]"
      />
    </TPanel>
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
.stat-row {
  display: grid;
  grid-template-columns: repeat(3, 1fr);
  gap: var(--space-2);
  margin-bottom: var(--space-4);
}
.dash {
  display: flex;
  flex-direction: column;
  gap: var(--space-3);
}
</style>
