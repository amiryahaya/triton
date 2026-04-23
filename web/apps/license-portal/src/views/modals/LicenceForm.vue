<script setup lang="ts">
import { computed, ref, watch } from 'vue';
import {
  TModal, TFormField, TInput, TSelect, TCheckbox, TButton,
} from '@triton/ui';
import type {
  Organisation,
  LicenceTier,
  ProductScope,
  CreateLicenceRequest,
} from '@triton/api-client';

const props = defineProps<{
  open: boolean;
  orgs: Organisation[];
}>();

const emit = defineEmits<{
  close: [];
  submit: [payload: CreateLicenceRequest];
}>();

const orgID = ref('');
const tier = ref<LicenceTier>('pro');
const productScope = ref<ProductScope>('legacy');
const seats = ref<string>('0');
const scans = ref<string>('0');
const days = ref<string>('365');
const notes = ref('');

const fReport = ref(false);
const fManage = ref(false);
const fComprehensive = ref(false);
const fDiffTrend = ref(false);
const fCustomPolicy = ref(false);
const fSSO = ref(false);

const submitError = ref('');

const seatsNum = computed(() => parseInt(seats.value, 10));
const scansNum = computed(() => parseInt(scans.value, 10));
const daysNum = computed(() => parseInt(days.value, 10));

const validationError = computed(() => {
  if (!orgID.value) return 'Select an organisation.';
  if (isNaN(seatsNum.value) || seatsNum.value < 0)
    return 'Seats must be 0 or greater.';
  if (isNaN(scansNum.value) || scansNum.value < 0)
    return 'Scans must be 0 or greater.';
  if (isNaN(daysNum.value) || daysNum.value < 1)
    return 'Days must be 1 or greater.';
  if (seatsNum.value === 0 && scansNum.value === 0)
    return 'At least one of seats or scans must be greater than 0.';
  if (notes.value.length > 1000)
    return 'Notes must be 1000 characters or fewer.';
  return '';
});

const canSubmit = computed(() => validationError.value === '');

watch(
  () => props.open,
  (open) => {
    if (!open) return;
    orgID.value = props.orgs[0]?.id ?? '';
    tier.value = 'pro';
    productScope.value = 'legacy';
    seats.value = '0';
    scans.value = '0';
    days.value = '365';
    notes.value = '';
    fReport.value = false;
    fManage.value = false;
    fComprehensive.value = false;
    fDiffTrend.value = false;
    fCustomPolicy.value = false;
    fSSO.value = false;
    submitError.value = '';
  },
  { immediate: true },
);

function submit() {
  if (!canSubmit.value) {
    submitError.value = validationError.value;
    return;
  }
  const payload: CreateLicenceRequest = {
    orgID: orgID.value,
    tier: tier.value,
    seats: seatsNum.value,
    days: daysNum.value,
    notes: notes.value || undefined,
    features: {
      report: fReport.value,
      manage: fManage.value,
      comprehensive_profile: fComprehensive.value,
      diff_trend: fDiffTrend.value,
      custom_policy: fCustomPolicy.value,
      sso: fSSO.value,
    },
    limits: scansNum.value > 0
      ? [{ metric: 'scans', window: 'total', cap: scansNum.value }]
      : [],
    product_scope: productScope.value,
  };
  emit('submit', payload);
}
</script>

<template>
  <TModal
    :open="open"
    title="Create licence"
    @close="emit('close')"
  >
    <div class="form">
      <TFormField label="Organisation" required>
        <TSelect v-model="orgID">
          <option value="" disabled>Select organisation</option>
          <option
            v-for="o in orgs"
            :key="o.id"
            :value="o.id"
          >{{ o.name }}</option>
        </TSelect>
      </TFormField>

      <TFormField label="Tier">
        <TSelect v-model="tier">
          <option value="free">Free</option>
          <option value="pro">Pro</option>
          <option value="enterprise">Enterprise</option>
        </TSelect>
      </TFormField>

      <TFormField
        label="Product scope"
        hint="Which product(s) this licence entitles"
      >
        <TSelect v-model="productScope">
          <option value="legacy">Legacy (both products)</option>
          <option value="report">Report Server only</option>
          <option value="manage">Manage Server only</option>
          <option value="bundle">Bundle (both, scoped)</option>
        </TSelect>
      </TFormField>

      <div class="row">
        <TFormField label="Seats" hint="0 = unlimited">
          <TInput
            v-model="seats"
            type="number"
            min="0"
            data-test="input-seats"
          />
        </TFormField>
        <TFormField label="Scans total" hint="0 = unlimited">
          <TInput
            v-model="scans"
            type="number"
            min="0"
            data-test="input-scans"
          />
        </TFormField>
        <TFormField label="Days valid">
          <TInput
            v-model="days"
            type="number"
            min="1"
            data-test="input-days"
          />
        </TFormField>
      </div>

      <TFormField label="Features">
        <div class="features">
          <TCheckbox v-model="fReport" label="Report server" />
          <TCheckbox v-model="fManage" label="Manage server" />
          <TCheckbox v-model="fComprehensive" label="Comprehensive profile" />
          <TCheckbox v-model="fDiffTrend" label="Diff & trend" />
          <TCheckbox v-model="fCustomPolicy" label="Custom policy" />
          <TCheckbox v-model="fSSO" label="SSO" />
        </div>
      </TFormField>

      <TFormField label="Notes">
        <TInput v-model="notes" />
      </TFormField>

      <div
        v-if="submitError"
        class="err"
        data-test="submit-error"
      >
        {{ submitError }}
      </div>
      <div
        v-else-if="validationError"
        class="hint"
        data-test="validation-hint"
      >
        {{ validationError }}
      </div>
    </div>

    <template #footer>
      <TButton
        variant="ghost"
        size="sm"
        @click="emit('close')"
      >Cancel</TButton>
      <TButton
        variant="primary"
        size="sm"
        :disabled="!canSubmit"
        data-test="submit-create"
        @click="submit"
      >Create</TButton>
    </template>
  </TModal>
</template>

<style scoped>
.form { display: flex; flex-direction: column; gap: var(--space-3); }
.row { display: grid; grid-template-columns: repeat(3, 1fr); gap: var(--space-2); }
.features {
  display: grid;
  grid-template-columns: repeat(2, 1fr);
  gap: var(--space-2);
}
.err { color: var(--unsafe); font-size: 0.76rem; }
.hint { color: var(--text-muted); font-size: 0.72rem; }
</style>
