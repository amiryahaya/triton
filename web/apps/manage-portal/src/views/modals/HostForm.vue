<script setup lang="ts">
import { ref, watch } from 'vue';
import { TModal, TFormField, TInput, TSelect, TButton } from '@triton/ui';
import type { Host, Zone, CreateHostReq } from '@triton/api-client';

const props = defineProps<{
  open: boolean;
  editing?: Host | null;
  zones: Zone[];
}>();

const emit = defineEmits<{
  close: [];
  submit: [payload: CreateHostReq];
}>();

const hostname = ref('');
const ip = ref('');
const zoneID = ref('');
const os = ref('');
const error = ref('');

watch(
  () => [props.open, props.editing],
  () => {
    if (!props.open) return;
    hostname.value = props.editing?.hostname ?? '';
    ip.value = props.editing?.ip ?? '';
    zoneID.value = props.editing?.zone_id ?? '';
    os.value = props.editing?.os ?? '';
    error.value = '';
  },
  { immediate: true }
);

function submit() {
  if (!hostname.value.trim()) {
    error.value = 'Hostname is required.';
    return;
  }
  emit('submit', {
    hostname: hostname.value.trim(),
    ip: ip.value.trim() || undefined,
    zone_id: zoneID.value || undefined,
    os: os.value.trim() || undefined,
  });
}
</script>

<template>
  <TModal
    :open="open"
    :title="editing ? 'Edit host' : 'New host'"
    @close="emit('close')"
  >
    <div class="host-form">
      <TFormField
        label="Hostname"
        required
        :error="error"
      >
        <TInput v-model="hostname" />
      </TFormField>
      <TFormField label="IP address">
        <TInput v-model="ip" />
      </TFormField>
      <TFormField label="Zone">
        <TSelect v-model="zoneID">
          <option value="">
            — None —
          </option>
          <option
            v-for="z in zones"
            :key="z.id"
            :value="z.id"
          >
            {{ z.name }}
          </option>
        </TSelect>
      </TFormField>
      <TFormField label="OS">
        <TInput v-model="os" />
      </TFormField>
    </div>
    <template #footer>
      <TButton
        variant="ghost"
        size="sm"
        @click="emit('close')"
      >
        Cancel
      </TButton>
      <TButton
        variant="primary"
        size="sm"
        @click="submit"
      >
        {{ editing ? 'Save' : 'Create' }}
      </TButton>
    </template>
  </TModal>
</template>

<style scoped>
.host-form {
  display: flex;
  flex-direction: column;
  gap: var(--space-3);
}
</style>
