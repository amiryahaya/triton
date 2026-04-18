export const VERSION = '0.0.0';

export {
  useTheme,
  type ThemeMode,
  type ResolvedTheme,
  type UseTheme,
} from './composables/useTheme';

export { default as TButton } from './atoms/TButton.vue';
export type { ButtonVariant, ButtonSize } from './atoms/TButton.vue';

export { default as TDot } from './atoms/TDot.vue';
export { default as TPill } from './atoms/TPill.vue';
export type { PillVariant } from './atoms/TPill.vue';

export { default as TInput } from './atoms/TInput.vue';
export { default as TSelect } from './atoms/TSelect.vue';
export { default as TFormField } from './atoms/TFormField.vue';

export { default as TToggle } from './atoms/TToggle.vue';
export { default as TCheckbox } from './atoms/TCheckbox.vue';

export { default as TAvatar } from './atoms/TAvatar.vue';
export { default as TKbd } from './atoms/TKbd.vue';

export { default as TStatCard } from './composite/TStatCard.vue';
export { default as TPanel } from './composite/TPanel.vue';
export { default as TDataTable } from './composite/TDataTable.vue';
export type { Column } from './composite/TDataTable.vue';
export { default as TModal } from './composite/TModal.vue';
export { default as TConfirmDialog } from './composite/TConfirmDialog.vue';
export { useFocusTrap } from './composables/useFocusTrap';
export { useToast } from './composables/useToast';
export type { ToastKind, ToastInput } from './composables/useToast';
export { default as TToastHost } from './composite/TToastHost.vue';
