<script setup lang="ts">
import TModal from './TModal.vue';
import TButton from '../atoms/TButton.vue';

withDefaults(
  defineProps<{
    open: boolean;
    title: string;
    message?: string;
    confirmLabel?: string;
    cancelLabel?: string;
    variant?: 'danger' | 'primary';
  }>(),
  {
    message: undefined,
    confirmLabel: 'Confirm',
    cancelLabel: 'Cancel',
    variant: 'danger',
  }
);

const emit = defineEmits<{ confirm: []; cancel: [] }>();
</script>

<template>
  <TModal
    :open="open"
    :title="title"
    @close="emit('cancel')"
  >
    <p v-if="message">
      {{ message }}
    </p>
    <slot />
    <template #footer>
      <TButton
        class="t-confirm-cancel"
        variant="ghost"
        size="sm"
        @click="emit('cancel')"
      >
        {{ cancelLabel }}
      </TButton>
      <TButton
        class="t-confirm-ok"
        :variant="variant"
        size="sm"
        @click="emit('confirm')"
      >
        {{ confirmLabel }}
      </TButton>
    </template>
  </TModal>
</template>
