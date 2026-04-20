<script setup lang="ts">
import { TModal, TButton } from '@triton/ui';
import TCodeBlock from '../../components/TCodeBlock.vue';

const props = defineProps<{
  open: boolean;
  email: string;
  tempPassword: string;
}>();

const emit = defineEmits<{ close: [] }>();
</script>

<template>
  <TModal
    :open="props.open"
    title="User created"
    width="min(520px, 92vw)"
    @close="emit('close')"
  >
    <p class="user-created-lede">
      Temporary password for <strong>{{ props.email }}</strong>. Shown once —
      copy it now and share securely.
    </p>
    <TCodeBlock :code="props.tempPassword" />
    <template #footer>
      <TButton
        variant="primary"
        size="sm"
        @click="emit('close')"
      >
        Done
      </TButton>
    </template>
  </TModal>
</template>

<style scoped>
.user-created-lede {
  margin: 0 0 var(--space-3);
  font-size: 0.82rem;
  line-height: 1.5;
  color: var(--text-muted);
}
.user-created-lede strong {
  color: var(--text);
  font-family: var(--font-mono);
}
</style>
