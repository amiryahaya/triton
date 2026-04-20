<script setup lang="ts">
import { onMounted } from 'vue';
import { useRouter } from 'vue-router';
import { TButton, TPill } from '@triton/ui';
import { useLicenceStore } from '../stores/licence';

const router = useRouter();
const licence = useLicenceStore();

onMounted(() => {
  void licence.fetch();
});

function reactivate() {
  router.push('/setup/license');
}
</script>

<template>
  <section class="licence-view">
    <header class="licence-head">
      <div>
        <h1>Licence</h1>
        <p class="licence-sub">
          Activation status for this Manage Server instance.
        </p>
      </div>
      <TButton
        variant="secondary"
        size="sm"
        @click="reactivate"
      >
        Re-activate
      </TButton>
    </header>

    <div class="licence-panel">
      <dl class="licence-dl">
        <dt>Status</dt>
        <dd>
          <TPill
            v-if="licence.summary"
            variant="safe"
          >
            Active
          </TPill>
          <TPill
            v-else-if="licence.loading"
            variant="neutral"
          >
            Loading…
          </TPill>
          <TPill
            v-else
            variant="warn"
          >
            Unknown
          </TPill>
        </dd>
      </dl>
      <p class="licence-note">
        A follow-up PR adds <code>GET /v1/admin/licence</code> which will
        surface tier, expiry, seat usage, and licence-server URL here.
        Until then, this panel only confirms that the Manage Server can
        reach its licence backend.
      </p>
    </div>
  </section>
</template>

<style scoped>
.licence-view {
  display: flex;
  flex-direction: column;
  gap: var(--space-4);
  padding: var(--space-4);
}
.licence-head {
  display: flex;
  align-items: flex-start;
  justify-content: space-between;
  gap: var(--space-3);
}
.licence-head h1 {
  font-family: var(--font-display);
  font-size: 1.4rem;
  margin: 0;
}
.licence-sub {
  color: var(--text-muted);
  font-size: 0.78rem;
  margin: var(--space-1) 0 0;
}
.licence-panel {
  border: 1px solid var(--border);
  border-radius: var(--radius);
  padding: var(--space-4);
  background: var(--bg-surface);
  display: flex;
  flex-direction: column;
  gap: var(--space-3);
}
.licence-dl {
  display: grid;
  grid-template-columns: max-content 1fr;
  gap: var(--space-2) var(--space-4);
  margin: 0;
  font-size: 0.85rem;
}
.licence-dl dt {
  color: var(--text-muted);
}
.licence-dl dd {
  margin: 0;
}
.licence-note {
  margin: 0;
  color: var(--text-muted);
  font-size: 0.78rem;
  line-height: 1.5;
}
.licence-note code {
  font-family: var(--font-mono);
  font-size: 0.72rem;
  padding: 1px 4px;
  background: var(--bg-code, var(--bg));
  border-radius: var(--radius-sm);
}
</style>
