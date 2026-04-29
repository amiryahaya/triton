<template>
  <div class="wizard-page">
    <!-- Sidebar -->
    <nav class="wizard-sidebar">
      <div
        v-for="(s, i) in steps"
        :key="i"
        class="wizard-step-item"
        :class="{ active: currentStep === i + 1, done: currentStep > i + 1 }"
        @click="maybeJumpTo(i + 1)"
      >
        <span class="step-number">{{ i + 1 }}</span>
        <span class="step-name">{{ s }}</span>
      </div>
    </nav>

    <!-- Main content area -->
    <main class="wizard-main">
      <!-- Steps 1-4: v-model pattern -->
      <component
        :is="stepComponent"
        v-if="currentStep < 5"
        v-model="state"
      />

      <!-- Step 5: explicit props + events -->
      <Step5Summary
        v-else
        :state="state"
        :all-hosts="allHosts"
        :loading="submitting"
        @go-step="currentStep = $event"
        @submit="submit"
      />

      <!-- Navigation footer (not shown on step 5 which has its own submit) -->
      <div v-if="currentStep < 5" class="wizard-footer">
        <button v-if="currentStep > 1" class="btn-secondary" @click="currentStep--">Back</button>
        <button class="btn-primary" :disabled="!canAdvance" @click="currentStep++">Next</button>
      </div>
    </main>
  </div>
</template>

<script setup lang="ts">
import { ref, computed, onMounted, defineAsyncComponent } from 'vue';
import { useRouter } from 'vue-router';
import type { Host } from '@triton/api-client';
import { useApiClient } from '../stores/apiClient';
import { useScanJobsStore } from '../stores/scanjobs';
import type { WizardState } from './enqueue/wizardTypes';
export type { WizardState };
import Step5Summary from './enqueue/Step5Summary.vue';

// Define async components once at module scope — not inside computed — so
// Vue's async-component machinery isn't re-created on every reactive update.
const Step1 = defineAsyncComponent(() => import('./enqueue/Step1JobType.vue'));
const Step2 = defineAsyncComponent(() => import('./enqueue/Step2Hosts.vue'));
const Step3 = defineAsyncComponent(() => import('./enqueue/Step3Schedule.vue'));
const Step4 = defineAsyncComponent(() => import('./enqueue/Step4Resources.vue'));

const router = useRouter();
const jobs = useScanJobsStore();

const steps = ['Job Type', 'Hosts', 'Schedule', 'Resources', 'Summary'];
const currentStep = ref(1);
const submitting = ref(false);
const allHosts = ref<Host[]>([]);

const state = ref<WizardState>({
  jobTypes:    [],
  profile:     'standard',
  hostIDs:     [],
  scheduleKey: 'immediately',
});

onMounted(async () => {
  allHosts.value = await useApiClient().get().listHosts();
});

const stepComponent = computed(() => {
  const map: Record<number, ReturnType<typeof defineAsyncComponent>> = {
    1: Step1,
    2: Step2,
    3: Step3,
    4: Step4,
  };
  return map[currentStep.value] ?? Step1;
});

const canAdvance = computed(() => {
  if (currentStep.value === 1) return state.value.jobTypes.length > 0;
  if (currentStep.value === 2) return state.value.hostIDs.length > 0;
  return true;
});

function maybeJumpTo(step: number) {
  if (step < currentStep.value || canAdvance.value) {
    currentStep.value = step;
  }
}

async function submit() {
  submitting.value = true;
  try {
    const isRecurring = !['immediately', 'once_at'].includes(state.value.scheduleKey);

    if (isRecurring && state.value.cronExpr) {
      await jobs.createSchedule({
        name:           state.value.scheduleName ?? '',
        job_types:      state.value.jobTypes as ('filesystem' | 'port_survey')[],
        host_ids:       state.value.hostIDs,
        profile:        state.value.profile as 'quick' | 'standard' | 'comprehensive',
        cron_expr:      state.value.cronExpr,
        max_cpu_pct:    state.value.maxCPUPct   ?? null,
        max_memory_mb:  state.value.maxMemoryMB ?? null,
        max_duration_s: state.value.maxDurationS ?? null,
      });
    }

    await jobs.enqueueBatch({
      job_types:      state.value.jobTypes as ('filesystem' | 'port_survey')[],
      host_ids:       state.value.hostIDs,
      profile:        state.value.profile as 'quick' | 'standard' | 'comprehensive',
      max_cpu_pct:    state.value.maxCPUPct   ?? null,
      max_memory_mb:  state.value.maxMemoryMB ?? null,
      max_duration_s: state.value.maxDurationS ?? null,
    });

    router.push('/operations/scan-jobs');
  } finally {
    submitting.value = false;
  }
}
</script>

<style scoped>
.wizard-page {
  display: flex;
  min-height: 100vh;
}

.wizard-sidebar {
  width: 220px;
  padding: 2rem 1rem;
  border-right: 1px solid var(--border);
  flex-shrink: 0;
}

.wizard-step-item {
  display: flex;
  align-items: center;
  gap: .75rem;
  padding: .6rem .75rem;
  border-radius: 6px;
  cursor: pointer;
  color: var(--text-muted);
  transition: background 0.15s, color 0.15s;
  user-select: none;
}

.wizard-step-item.active {
  background: var(--surface-2);
  color: var(--text);
  font-weight: 600;
}

.wizard-step-item.done {
  color: var(--accent);
}

.step-number {
  width: 24px;
  height: 24px;
  border-radius: 50%;
  background: var(--surface-3);
  display: flex;
  align-items: center;
  justify-content: center;
  font-size: .75rem;
  flex-shrink: 0;
}

.wizard-main {
  flex: 1;
  padding: 2rem;
  max-width: 720px;
}

.wizard-footer {
  display: flex;
  gap: 1rem;
  margin-top: 2rem;
}

.btn-primary {
  padding: 0.6rem 1.2rem;
  background: var(--color-primary, #2563eb);
  color: white;
  border: none;
  border-radius: var(--radius-sm, 6px);
  font-size: 0.9rem;
  font-weight: 600;
  cursor: pointer;
  transition: opacity 0.15s;
}

.btn-primary:disabled {
  opacity: 0.45;
  cursor: not-allowed;
}

.btn-primary:not(:disabled):hover {
  opacity: 0.85;
}

.btn-secondary {
  padding: 0.6rem 1.2rem;
  background: transparent;
  color: var(--text, #111);
  border: 1px solid var(--border, #d1d5db);
  border-radius: var(--radius-sm, 6px);
  font-size: 0.9rem;
  font-weight: 500;
  cursor: pointer;
  transition: background 0.15s;
}

.btn-secondary:hover {
  background: var(--surface-2, #f3f4f6);
}
</style>
