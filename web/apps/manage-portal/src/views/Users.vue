<script setup lang="ts">
import { onMounted, ref } from 'vue';
import {
  TDataTable,
  TButton,
  TPill,
  useToast,
  type Column,
  type PillVariant,
} from '@triton/ui';
import { useUsersStore } from '../stores/users';
import UserCreateForm from './modals/UserCreateForm.vue';
import UserCreatedResult from './modals/UserCreatedResult.vue';
import type { ManageUser, CreateUserReq, CreateUserResp } from '@triton/api-client';

const users = useUsersStore();
const toast = useToast();

const createOpen = ref(false);
const created = ref<CreateUserResp | null>(null);

const columns: Column<ManageUser>[] = [
  { key: 'email', label: 'Email' },
  { key: 'name', label: 'Name' },
  { key: 'role', label: 'Role' },
  { key: 'must_change_pw', label: 'Must change pw?' },
  { key: 'created_at', label: 'Created' },
];

// TPill variants: admin → enterprise (distinct weight), network_engineer →
// info. Covers only the two roles the backend accepts today.
const roleVariant: Record<ManageUser['role'], PillVariant> = {
  admin: 'enterprise',
  network_engineer: 'info',
};

onMounted(() => {
  void users.fetch();
});

async function onCreate(req: CreateUserReq) {
  try {
    const resp = await users.create(req);
    toast.success({ title: 'User created', description: resp.email });
    createOpen.value = false;
    created.value = resp;
  } catch (e) {
    toast.error({ title: 'Create failed', description: String(e) });
  }
}
</script>

<template>
  <section class="users-view">
    <header class="users-head">
      <div>
        <h1>Users</h1>
        <p class="users-sub">Manage portal operators. Temporary passwords are shown once at creation.</p>
      </div>
      <TButton
        variant="primary"
        size="sm"
        @click="createOpen = true"
      >
        New user
      </TButton>
    </header>

    <TDataTable
      :columns="columns"
      :rows="users.items"
      row-key="id"
      :empty-text="users.loading ? 'Loading…' : 'No users yet.'"
    >
      <template #[`cell:role`]="{ row }">
        <TPill :variant="roleVariant[row.role] ?? 'neutral'">
          {{ row.role }}
        </TPill>
      </template>
      <template #[`cell:must_change_pw`]="{ row }">
        <span v-if="row.must_change_pw">yes</span>
        <span v-else>no</span>
      </template>
    </TDataTable>

    <UserCreateForm
      :open="createOpen"
      @close="createOpen = false"
      @submit="onCreate"
    />
    <UserCreatedResult
      :open="!!created"
      :email="created?.email ?? ''"
      :temp-password="created?.temp_password ?? ''"
      @close="created = null"
    />
  </section>
</template>

<style scoped>
.users-view {
  display: flex;
  flex-direction: column;
  gap: var(--space-4);
  padding: var(--space-4);
}
.users-head {
  display: flex;
  align-items: flex-start;
  justify-content: space-between;
  gap: var(--space-3);
}
.users-head h1 {
  font-family: var(--font-display);
  font-size: 1.4rem;
  margin: 0;
}
.users-sub {
  color: var(--text-muted);
  font-size: 0.78rem;
  margin: var(--space-1) 0 0;
}
</style>
