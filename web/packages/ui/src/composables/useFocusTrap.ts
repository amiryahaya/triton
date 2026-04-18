import { onMounted, onUnmounted, watch, type Ref } from 'vue';

/**
 * Traps keyboard focus inside the given element. Tab and Shift-Tab cycle
 * within `containerRef`'s focusable descendants while the trap is active.
 *
 * Optional `activeRef` — if supplied, the trap activates when it flips to
 * true (e.g. a modal opens), moves focus into the container, and
 * deactivates when it flips back, restoring focus to whatever was focused
 * before activation. Pass `undefined` if the host component is already
 * conditionally mounted (less common — most hosts keep the trap component
 * mounted and toggle an `open` prop).
 *
 * ESC is NOT handled here — the host decides close behaviour.
 */
export function useFocusTrap(
  containerRef: Ref<HTMLElement | null>,
  activeRef?: Ref<boolean>
) {
  let lastFocused: HTMLElement | null = null;

  const focusableSel =
    'button, [href], input, select, textarea, [tabindex]:not([tabindex="-1"])';

  function trap(ev: KeyboardEvent) {
    if (ev.key !== 'Tab' || !containerRef.value) return;
    const focusable = containerRef.value.querySelectorAll<HTMLElement>(focusableSel);
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

  function focusFirstInside() {
    // Wait a microtask so v-if / Teleport has materialised the DOM
    // before we try to query it.
    queueMicrotask(() => {
      const first = containerRef.value?.querySelector<HTMLElement>(focusableSel);
      first?.focus();
    });
  }

  function activate() {
    lastFocused = document.activeElement as HTMLElement | null;
    focusFirstInside();
  }

  function deactivate() {
    lastFocused?.focus();
    lastFocused = null;
  }

  onMounted(() => {
    document.addEventListener('keydown', trap);
    // No activeRef → assume always-active (legacy callers).
    if (!activeRef) activate();
  });

  onUnmounted(() => {
    document.removeEventListener('keydown', trap);
    if (!activeRef) deactivate();
  });

  if (activeRef) {
    watch(
      activeRef,
      (now) => (now ? activate() : deactivate()),
      { immediate: true }
    );
  }
}
