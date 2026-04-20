<script setup lang="ts">
import TModal from './TModal.vue';
import TButton from '../atoms/TButton.vue';

// TModal renders a Teleport root, so Vue cannot auto-inherit fallthrough
// attributes (e.g. data-test="confirm-dialog") onto a single DOM element.
// We disable inheritance here and manually v-bind $attrs onto the body
// wrapper so test hooks + aria-describedby style attributes land on a
// real element inside the teleported modal.
defineOptions({ inheritAttrs: false });

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
    <div
      class="t-confirm-body"
      v-bind="$attrs"
    >
      <p v-if="message">
        {{ message }}
      </p>
      <slot />
    </div>
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
