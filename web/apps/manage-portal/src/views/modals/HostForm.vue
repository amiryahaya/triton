<script setup lang="ts">
import { ref, computed, watch } from 'vue';
import { TModal, TFormField, TInput, TSelect, TButton } from '@triton/ui';
import type { Host, Tag, CreateHostReq } from '@triton/api-client';
import { useCredentialsStore } from '../../stores/credentials';

const props = defineProps<{
  open: boolean;
  editing?: Host | null;
  tags: Tag[];
}>();

const emit = defineEmits<{
  close: [];
  submit: [payload: CreateHostReq];
}>();

const credStore = useCredentialsStore();

const hostname = ref('');
const ip = ref('');
const os = ref('');
const selectedTagIDs = ref<string[]>([]);
const error = ref('');
const credentialsRef = ref<string | null>(null);
const accessPort = ref<number>(22);

watch(
  () => [props.open, props.editing],
  () => {
    if (!props.open) return;
    credStore.fetch();
    hostname.value = props.editing?.hostname ?? '';
    ip.value = props.editing?.ip ?? '';
    os.value = props.editing?.os ?? '';
    selectedTagIDs.value = props.editing?.tags.map(t => t.id) ?? [];
    credentialsRef.value = props.editing?.credentials_ref ?? null;
    accessPort.value = props.editing?.access_port ?? 22;
    error.value = '';
  },
  { immediate: true }
);

watch(credentialsRef, (id) => {
  if (!id) { accessPort.value = 22; return; }
  const cred = credStore.items.find(c => c.id === id);
  if (!cred) return;
  if (cred.auth_type === 'winrm-password') accessPort.value = 5985;
  else accessPort.value = 22;
});

const credOptions = computed(() => [
  { value: null, label: '— none —' },
  ...credStore.items.map(c => ({ value: c.id, label: `${c.name} (${c.auth_type})` })),
]);

function submit() {
  if (!ip.value.trim()) {
    error.value = 'IP address is required.';
    return;
  }
  emit('submit', {
    ip: ip.value.trim(),
    hostname: hostname.value.trim() || undefined,
    os: os.value.trim() || undefined,
    tag_ids: selectedTagIDs.value,
    credentials_ref: credentialsRef.value ?? null,
    access_port: accessPort.value,
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
      <TFormField label="Hostname">
        <TInput v-model="hostname" />
      </TFormField>
      <TFormField
        label="IP address"
        required
        :error="error"
      >
        <TInput v-model="ip" />
      </TFormField>
      <TFormField label="OS">
        <TInput v-model="os" />
      </TFormField>
      <TFormField label="Tags">
        <div class="tag-multi-select">
          <label
            v-for="tag in tags"
            :key="tag.id"
            class="tag-checkbox"
          >
            <input
              type="checkbox"
              :value="tag.id"
              v-model="selectedTagIDs"
            />
            <span
              class="tag-chip"
              :style="{ background: tag.color }"
            >{{ tag.name }}</span>
          </label>
          <span
            v-if="!tags.length"
            class="no-tags"
          >No tags defined yet.</span>
        </div>
      </TFormField>
      <TFormField label="Credential">
        <TSelect v-model="credentialsRef">
          <option
            v-for="opt in credOptions"
            :key="opt.value ?? '__none__'"
            :value="opt.value"
          >
            {{ opt.label }}
          </option>
        </TSelect>
      </TFormField>
      <TFormField label="Access Port">
        <TInput
          v-model.number="accessPort"
          type="number"
          :min="1"
          :max="65535"
        />
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
.tag-multi-select {
  display: flex;
  flex-wrap: wrap;
  gap: var(--space-2);
  padding: var(--space-1) 0;
}
.tag-checkbox {
  display: inline-flex;
  align-items: center;
  gap: var(--space-1);
  cursor: pointer;
}
.tag-checkbox input[type='checkbox'] {
  accent-color: var(--accent-strong);
  cursor: pointer;
}
.tag-chip {
  display: inline-flex;
  align-items: center;
  padding: 2px 8px;
  border-radius: var(--radius-full, 9999px);
  font-size: 0.72rem;
  font-weight: 500;
  color: #fff;
  white-space: nowrap;
}
.no-tags {
  font-size: 0.78rem;
  color: var(--text-muted);
}
</style>
