<template>
  <div class="step-content">
    <h2 class="step-title">Resource Limits</h2>
    <p class="step-subtitle">All limits default to 0 = unlimited.</p>

    <div class="slider-group">
      <!-- CPU -->
      <div class="slider-row">
        <label class="slider-label">CPU limit</label>
        <div class="slider-container">
          <input type="range" min="0" max="100" step="5" v-model.number="cpu" class="slider" />
          <span class="slider-value">{{ cpu === 0 ? 'Unlimited' : cpu + '%' }}</span>
        </div>
      </div>

      <!-- Memory -->
      <div class="slider-row">
        <label class="slider-label">Memory limit</label>
        <div class="slider-container">
          <input type="range" min="0" max="32768" step="512" v-model.number="memory" class="slider" />
          <span class="slider-value">{{ memory === 0 ? 'Unlimited' : formatMB(memory) }}</span>
        </div>
        <span class="slider-hint">Soft cap — watchdog kills at 1.5×</span>
      </div>

      <!-- Duration -->
      <div class="slider-row">
        <label class="slider-label">Max duration</label>
        <div class="slider-container">
          <input type="range" min="0" max="86400" step="1800" v-model.number="duration" class="slider" />
          <span class="slider-value">{{ duration === 0 ? 'Unlimited' : formatSeconds(duration) }}</span>
        </div>
        <span class="slider-hint">Wall-clock budget per job</span>
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref, watch } from 'vue';
import type { WizardState } from './wizardTypes';

const props = defineProps<{ modelValue: WizardState }>();
const emit = defineEmits<{ 'update:modelValue': [WizardState] }>();

const cpu      = ref(props.modelValue.maxCPUPct    ?? 0);
const memory   = ref(props.modelValue.maxMemoryMB  ?? 0);
const duration = ref(props.modelValue.maxDurationS ?? 0);

function formatMB(mb: number): string {
  return mb >= 1024 ? `${(mb / 1024).toFixed(1)} GB` : `${mb} MB`;
}

function formatSeconds(s: number): string {
  const h = Math.floor(s / 3600);
  const m = Math.floor((s % 3600) / 60);
  return h > 0 ? `${h}h ${m > 0 ? m + 'm' : ''}`.trim() : `${m}m`;
}

watch([cpu, memory, duration], () => {
  emit('update:modelValue', {
    ...props.modelValue,
    maxCPUPct:    cpu.value || null,
    maxMemoryMB:  memory.value || null,
    maxDurationS: duration.value || null,
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

.slider-group {
  display: flex;
  flex-direction: column;
  gap: var(--space-4);
}

.slider-row {
  display: flex;
  flex-direction: column;
  gap: var(--space-2);
  padding: var(--space-3);
  border: 1px solid var(--border);
  border-radius: var(--radius-sm);
  background: var(--bg-muted, #f9fafb);
}

.slider-label {
  font-size: 0.82rem;
  font-weight: 600;
  color: var(--text-secondary);
}

.slider-container {
  display: flex;
  align-items: center;
  gap: var(--space-3);
}

.slider {
  flex: 1;
  height: 24px;
  -webkit-appearance: none;
  appearance: none;
  border-radius: 12px;
  background: linear-gradient(to right, var(--color-primary, #2563eb) 0%, var(--color-primary, #2563eb) 50%, var(--border) 50%, var(--border) 100%);
  outline: none;
  cursor: pointer;
}

.slider::-webkit-slider-thumb {
  -webkit-appearance: none;
  appearance: none;
  width: 20px;
  height: 20px;
  border-radius: 50%;
  background: var(--color-primary, #2563eb);
  cursor: pointer;
  border: 2px solid white;
  box-shadow: 0 2px 4px rgba(0, 0, 0, 0.1);
}

.slider::-moz-range-thumb {
  width: 20px;
  height: 20px;
  border-radius: 50%;
  background: var(--color-primary, #2563eb);
  cursor: pointer;
  border: 2px solid white;
  box-shadow: 0 2px 4px rgba(0, 0, 0, 0.1);
}

.slider::-webkit-slider-runnable-track {
  width: 100%;
  height: 24px;
  background: transparent;
}

.slider::-moz-range-track {
  background: transparent;
  border: none;
}

.slider-value {
  font-size: 0.9rem;
  font-weight: 600;
  color: var(--text-primary);
  min-width: 70px;
  text-align: right;
}

.slider-hint {
  font-size: 0.75rem;
  color: var(--text-muted);
  font-style: italic;
}
</style>
