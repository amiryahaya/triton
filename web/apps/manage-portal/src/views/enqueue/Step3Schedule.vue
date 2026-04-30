<template>
  <div class="step-content">
    <h2 class="step-title">Schedule</h2>

    <div class="radio-group">
      <label v-for="opt in options" :key="opt.key" class="radio-card"
             :class="{ selected: selection === opt.key }">
        <input type="radio" :value="opt.key" v-model="selection" />
        <span class="radio-label">{{ opt.label }}</span>

        <!-- Inline controls for parameterised options -->
        <template v-if="selection === opt.key && opt.key === 'daily'">
          <div class="inline-group">
            at <input type="time" v-model="dailyTime" class="t-input inline" />
          </div>
        </template>
        <template v-if="selection === opt.key && opt.key === 'weekly'">
          <div class="inline-group">
            on
            <select v-model="weeklyDay" class="t-select inline">
              <option v-for="(d, i) in days" :key="i" :value="i">{{ d }}</option>
            </select>
            at <input type="time" v-model="weeklyTime" class="t-input inline" />
          </div>
        </template>
        <template v-if="selection === opt.key && opt.key === 'monthly'">
          <div class="inline-group">
            day <input type="number" v-model.number="monthlyDay" min="1" max="31" class="t-input inline narrow" />
          </div>
        </template>
      </label>
    </div>

    <!-- Schedule name — shown only for recurring options -->
    <div v-if="isRecurring" class="field mt-4">
      <label class="field-label">Schedule name <span class="required">*</span></label>
      <input type="text" v-model="scheduleName" class="t-input"
             placeholder="e.g. Weekly infra scan" />
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref, computed, watch } from 'vue';
import type { WizardState } from './wizardTypes';

const props = defineProps<{ modelValue: WizardState }>();
const emit = defineEmits<{ 'update:modelValue': [WizardState] }>();

// 'once_at' is omitted — BatchEnqueueReq has no scheduled_at field yet.
// Immediate + recurring cron options are the supported modes.
const options = [
  { key: 'immediately', label: 'Run immediately' },
  { key: 'hourly',      label: 'Hourly' },
  { key: 'daily',       label: 'Daily at' },
  { key: 'weekly',      label: 'Weekly on' },
  { key: 'monthly',     label: 'Monthly on day' },
];
const days = ['Sunday', 'Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday'];

const selection = ref<string>(props.modelValue.scheduleKey ?? 'immediately');
const onceAt     = ref(props.modelValue.onceAt ?? '');
const dailyTime  = ref(props.modelValue.dailyTime ?? '02:00');
const weeklyDay  = ref(props.modelValue.weeklyDay ?? 1);
const weeklyTime = ref(props.modelValue.weeklyTime ?? '02:00');
const monthlyDay = ref(props.modelValue.monthlyDay ?? 1);
const scheduleName = ref(props.modelValue.scheduleName ?? '');

const isRecurring = computed(() => !['immediately', 'once_at'].includes(selection.value));

function buildCronExpr(): string | null {
  switch (selection.value) {
    case 'hourly':   return '0 * * * *';
    case 'daily': {
      const [h] = dailyTime.value.split(':');
      return `0 ${parseInt(h)} * * *`;
    }
    case 'weekly': {
      const [h] = weeklyTime.value.split(':');
      return `0 ${parseInt(h)} * * ${weeklyDay.value}`;
    }
    case 'monthly':  return `0 2 ${monthlyDay.value} * *`;
    default:         return null;
  }
}

watch([selection, onceAt, dailyTime, weeklyDay, weeklyTime, monthlyDay, scheduleName], () => {
  emit('update:modelValue', {
    ...props.modelValue,
    scheduleKey:   selection.value,
    onceAt:        selection.value === 'once_at' ? onceAt.value : undefined,
    cronExpr:      buildCronExpr() ?? undefined,
    scheduleName:  isRecurring.value ? scheduleName.value : undefined,
    dailyTime:     dailyTime.value,
    weeklyDay:     weeklyDay.value,
    weeklyTime:    weeklyTime.value,
    monthlyDay:    monthlyDay.value,
  });
}, { immediate: true });
</script>

<style scoped>
.step-content {
  display: flex;
  flex-direction: column;
  gap: var(--space-4);
}

.step-title {
  font-family: var(--font-display);
  font-size: 1.1rem;
  margin: 0;
}

.step-subtitle {
  color: var(--text-muted);
  font-size: 0.85rem;
  margin: 0;
}

.radio-group {
  display: flex;
  flex-direction: column;
  gap: var(--space-2);
}

.radio-card {
  display: flex;
  align-items: flex-start;
  gap: var(--space-3);
  padding: var(--space-3);
  border: 1px solid var(--border);
  border-radius: var(--radius-sm);
  cursor: pointer;
  transition: border-color 0.15s, background 0.15s;
  flex-wrap: wrap;
}

.radio-card:hover {
  border-color: var(--color-primary, #2563eb);
}

.radio-card.selected {
  border-color: var(--color-primary, #2563eb);
  background: color-mix(in srgb, var(--color-primary, #2563eb) 6%, transparent);
}

.radio-card input[type="radio"] {
  margin-top: 0.15rem;
  flex-shrink: 0;
}

.radio-label {
  flex: 0 0 auto;
  font-size: 0.9rem;
}

.inline-group {
  display: flex;
  align-items: center;
  gap: var(--space-2);
  font-size: 0.9rem;
}

.t-input {
  padding: 0.4rem 0.6rem;
  border: 1px solid var(--border);
  border-radius: var(--radius-sm);
  font-size: 0.875rem;
  background: var(--bg-surface);
  color: var(--text-primary);
  box-sizing: border-box;
}

.t-input:focus {
  outline: none;
  border-color: var(--color-primary, #2563eb);
}

.t-input.inline {
  width: auto;
  min-width: 120px;
}

.t-input.inline.narrow {
  width: 70px;
}

.t-input.inline.mt-2 {
  width: 100%;
  margin-top: var(--space-2);
}

.t-select {
  padding: 0.4rem 0.6rem;
  border: 1px solid var(--border);
  border-radius: var(--radius-sm);
  font-size: 0.875rem;
  background: var(--bg-surface);
  color: var(--text-primary);
  box-sizing: border-box;
}

.t-select:focus {
  outline: none;
  border-color: var(--color-primary, #2563eb);
}

.t-select.inline {
  width: auto;
  min-width: 100px;
}

.field {
  display: flex;
  flex-direction: column;
  gap: var(--space-1);
}

.field-label {
  font-size: 0.82rem;
  font-weight: 600;
  color: var(--text-secondary);
}

.required {
  color: #d32f2f;
}

.mt-4 {
  margin-top: var(--space-4);
}
</style>
