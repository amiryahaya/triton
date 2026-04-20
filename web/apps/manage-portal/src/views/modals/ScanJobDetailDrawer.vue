<script setup lang="ts">
import { watch } from 'vue';
import { TButton } from '@triton/ui';
import { useScanJobsStore } from '../../stores/scanjobs';

const props = defineProps<{ open: boolean; jobID: string | null }>();
const emit = defineEmits<{ close: [] }>();

const store = useScanJobsStore();

// Fetch detail whenever the drawer opens with an id OR the id changes
// while the drawer is already open.
watch(
  () => [props.open, props.jobID] as const,
  async ([open, id]) => {
    if (open && id) await store.getDetail(id);
  },
  { immediate: true }
);

async function refresh() {
  if (props.jobID) await store.getDetail(props.jobID);
}
</script>

<template>
  <div
    v-if="props.open"
    class="drawer-backdrop"
    @click="emit('close')"
  >
    <aside
      class="drawer"
      role="dialog"
      aria-label="Scan job detail"
      @click.stop
    >
      <header class="drawer-head">
        <h2>Scan Job</h2>
        <button
          class="close"
          aria-label="Close"
          @click="emit('close')"
        >
          ×
        </button>
      </header>
      <div
        v-if="store.selected && store.selected.id === props.jobID"
        class="body"
      >
        <dl>
          <dt>ID</dt>
          <dd>{{ store.selected.id }}</dd>
          <dt>Status</dt>
          <dd>{{ store.selected.status }}</dd>
          <dt>Profile</dt>
          <dd>{{ store.selected.profile }}</dd>
          <dt>Host</dt>
          <dd>{{ store.selected.host_id ?? '—' }}</dd>
          <dt>Zone</dt>
          <dd>{{ store.selected.zone_id ?? '—' }}</dd>
          <dt>Cancel requested</dt>
          <dd>{{ store.selected.cancel_requested ? 'yes' : 'no' }}</dd>
          <dt>Worker</dt>
          <dd>{{ store.selected.worker_id ?? '—' }}</dd>
          <dt>Enqueued</dt>
          <dd>{{ store.selected.enqueued_at }}</dd>
          <dt>Started</dt>
          <dd>{{ store.selected.started_at ?? '—' }}</dd>
          <dt>Finished</dt>
          <dd>{{ store.selected.finished_at ?? '—' }}</dd>
          <dt>Heartbeat</dt>
          <dd>{{ store.selected.running_heartbeat_at ?? '—' }}</dd>
          <dt>Progress</dt>
          <dd>{{ store.selected.progress_text || '—' }}</dd>
          <dt>Error</dt>
          <dd>{{ store.selected.error_message || '—' }}</dd>
        </dl>
        <div class="actions">
          <TButton
            variant="ghost"
            size="sm"
            @click="refresh"
          >
            Refresh
          </TButton>
        </div>
      </div>
      <div
        v-else
        class="body loading"
      >
        Loading…
      </div>
    </aside>
  </div>
</template>

<style scoped>
.drawer-backdrop {
  position: fixed;
  inset: 0;
  background: rgba(0, 0, 0, 0.24);
  z-index: 50;
}
.drawer {
  position: fixed;
  top: 0;
  right: 0;
  bottom: 0;
  width: 440px;
  max-width: 96vw;
  background: var(--bg-surface);
  box-shadow: -8px 0 24px rgba(0, 0, 0, 0.12);
  padding: var(--space-4);
  z-index: 51;
  overflow-y: auto;
  display: flex;
  flex-direction: column;
  gap: var(--space-3);
}
.drawer-head {
  display: flex;
  align-items: center;
  justify-content: space-between;
}
.drawer-head h2 {
  font-family: var(--font-display);
  font-size: 1.1rem;
  margin: 0;
}
.close {
  background: transparent;
  border: none;
  font-size: 1.6rem;
  line-height: 1;
  cursor: pointer;
  color: var(--text-muted);
  padding: 0 var(--space-1);
}
.close:hover { color: var(--text-primary); }
.body.loading {
  color: var(--text-muted);
  font-size: 0.85rem;
}
dl {
  display: grid;
  grid-template-columns: 130px 1fr;
  gap: var(--space-1) var(--space-3);
  margin: 0;
}
dt {
  color: var(--text-muted);
  font-size: 0.78rem;
}
dd {
  font-family: var(--font-mono);
  font-size: 0.82rem;
  word-break: break-all;
  margin: 0;
}
.actions {
  display: flex;
  justify-content: flex-end;
  margin-top: var(--space-2);
}
</style>
