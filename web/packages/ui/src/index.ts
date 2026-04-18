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
