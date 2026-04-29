<template>
  <div class="step-content">
    <h2 class="step-title">Job Type</h2>
    <p class="step-subtitle">Select one or more scan types to run.</p>

    <div class="checkbox-group">
      <label class="checkbox-card" :class="{ selected: modelValue.jobTypes.includes('port_survey') }">
        <input type="checkbox" value="port_survey"
               :checked="modelValue.jobTypes.includes('port_survey')"
               @change="toggle('port_survey')" />
        <div>
          <strong>Port Survey</strong>
          <span>Maps open ports using fingerprintx. No credential required.</span>
        </div>
      </label>

      <label class="checkbox-card" :class="{ selected: modelValue.jobTypes.includes('filesystem') }">
        <input type="checkbox" value="filesystem"
               :checked="modelValue.jobTypes.includes('filesystem')"
               @change="toggle('filesystem')" />
        <div>
          <strong>Filesystem (SSH)</strong>
          <span>Crypto asset scan via SSH or enrolled agent.</span>
        </div>
      </label>
    </div>

    <div class="field mt-4">
      <label class="field-label">Profile</label>
      <select class="t-select" :value="modelValue.profile" @change="setProfile(($event.target as HTMLSelectElement).value)">
        <option value="quick">Quick</option>
        <option value="standard">Standard</option>
        <option value="comprehensive">Comprehensive</option>
      </select>
    </div>
  </div>
</template>

<script setup lang="ts">
import type { WizardState } from './wizardTypes';

const props = defineProps<{ modelValue: WizardState }>();
const emit = defineEmits<{ 'update:modelValue': [WizardState] }>();

function toggle(jt: string) {
  const types = props.modelValue.jobTypes.includes(jt)
    ? props.modelValue.jobTypes.filter(t => t !== jt)
    : [...props.modelValue.jobTypes, jt];
  emit('update:modelValue', { ...props.modelValue, jobTypes: types });
}

function setProfile(profile: string) {
  emit('update:modelValue', { ...props.modelValue, profile });
}
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

.checkbox-group {
  display: flex;
  flex-direction: column;
  gap: var(--space-2);
}

.checkbox-card {
  display: flex;
  align-items: flex-start;
  gap: var(--space-3);
  padding: var(--space-3);
  border: 1px solid var(--border);
  border-radius: var(--radius-sm);
  cursor: pointer;
  transition: border-color 0.15s, background 0.15s;
}

.checkbox-card:hover {
  border-color: var(--color-primary, #2563eb);
}

.checkbox-card.selected {
  border-color: var(--color-primary, #2563eb);
  background: color-mix(in srgb, var(--color-primary, #2563eb) 6%, transparent);
}

.checkbox-card input[type="checkbox"] {
  margin-top: 0.15rem;
  flex-shrink: 0;
}

.checkbox-card div {
  display: flex;
  flex-direction: column;
  gap: var(--space-1);
}

.checkbox-card strong {
  font-size: 0.9rem;
}

.checkbox-card span {
  font-size: 0.78rem;
  color: var(--text-muted);
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

.mt-4 {
  margin-top: var(--space-4);
}

.t-select {
  width: 100%;
  padding: 0.4rem 0.6rem;
  border: 1px solid var(--border);
  border-radius: var(--radius-sm);
  font-size: 0.875rem;
  background: var(--bg-surface);
  color: var(--text-primary);
}
</style>
