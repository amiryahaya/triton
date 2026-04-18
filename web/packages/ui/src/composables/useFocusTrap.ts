import { onMounted, onUnmounted, type Ref } from 'vue';

/**
 * Traps keyboard focus inside the given element while mounted.
 * ESC bubble-up is allowed — host component decides close behaviour.
 */
export function useFocusTrap(containerRef: Ref<HTMLElement | null>) {
  let lastFocused: HTMLElement | null = null;

  function trap(ev: KeyboardEvent) {
    if (ev.key !== 'Tab' || !containerRef.value) return;
    const focusable = containerRef.value.querySelectorAll<HTMLElement>(
      'button, [href], input, select, textarea, [tabindex]:not([tabindex="-1"])'
    );
    if (focusable.length === 0) return;
    const first = focusable[0]!;
    const last = focusable[focusable.length - 1]!;
    if (ev.shiftKey && document.activeElement === first) {
      ev.preventDefault();
      last.focus();
    } else if (!ev.shiftKey && document.activeElement === last) {
      ev.preventDefault();
      first.focus();
    }
  }

  onMounted(() => {
    lastFocused = document.activeElement as HTMLElement | null;
    const first = containerRef.value?.querySelector<HTMLElement>(
      'button, [href], input, select, textarea, [tabindex]:not([tabindex="-1"])'
    );
    first?.focus();
    document.addEventListener('keydown', trap);
  });

  onUnmounted(() => {
    document.removeEventListener('keydown', trap);
    lastFocused?.focus();
  });
}
