<script lang="ts">
  // Human identities — one per email, with two independent capabilities:
  //   console  → an `admin_accounts` row (role admin/read_only)
  //   gateway  → a `users` row (portal sign-in, API keys, workspace memberships)
  // The CARD LIST carries the full state (role badge, workspace membership
  // chips) plus Disable/Enable per capability; the Edit modal owns profile and
  // access level, including removal ("No access" + Save deletes the
  // capability after an impact confirm). Workspace membership is managed
  // exclusively on the workspace pages. Service accounts have their own tab —
  // this list is humans only.
  import { adminApi } from '#lib/api-client.js';
  import { extractError, fetchAllPages } from '#lib/api-helpers.js';
  import type { UserResponse, AdminAccountResponse } from '#lib/api-types.js';
  import Modal from '#lib/components/Modal.svelte';
  import ImpactModal from '#lib/components/ImpactModal.svelte';
  import ConfirmDialog from '#lib/components/ConfirmDialog.svelte';
  import Skeleton from '#lib/components/Skeleton.svelte';
  import EmptyState from '#lib/components/EmptyState.svelte';
  import FormError from '#lib/components/forms/FormError.svelte';
  import ScopePicker, { type ScopeOption } from '#lib/components/forms/ScopePicker.svelte';
  import IdentityCard, { type Identity } from '#lib/components/auth/IdentityCard.svelte';
  import { usePeriodicLoad, useDirtyForm } from '#lib/hooks.svelte.js';
  import { toast } from '#lib/toast.svelte.js';
  import { page } from '$app/state';

  let isSystemTenant = $derived(page.data?.user?.tenant_slug === 'system');

  let identities = $state<Identity[]>([]);
  let accountsLoading = $state(true);
  let loadError = $state('');
  let authMode = $state('internal');
  let isOidc = $derived(authMode === 'oidc');
  // Per-identity busy key so one slow action never greys out unrelated cards.
  let busyEmail = $state<string | null>(null);
  const dirty = useDirtyForm();

  // Add/Edit modal — staged form, one explicit Save. `mode` decides whether the
  // email field is editable and which grants are creations vs changes.
  let modalMode = $state<'add' | 'edit' | null>(null);
  let editing = $state<Identity | null>(null);
  let formEmail = $state('');
  let formDisplayName = $state('');
  let formPassword = $state('');
  // 'none' | 'granted' (OIDC/system) | 'read_only' | 'admin' (internal role)
  let formConsole = $state('none');
  let formGateway = $state('none');
  let formError = $state('');
  let formBusy = $state(false);

  // Confirm dialogs: card Disable confirms its consequences; a Save that
  // removes access ("No access" picked in the modal) previews its impact.
  let confirmDisable = $state<{ identity: Identity; plane: 'console' | 'gateway' } | null>(null);
  let impactModal = $state<{
    open: boolean; title: string; message: string; affectedKeys: number; affectedUsers: number;
    affectedSessions: number; confirmLabel: string; onconfirm: () => void;
  }>({ open: false, title: '', message: '', affectedKeys: 0, affectedUsers: 0, affectedSessions: 0, confirmLabel: 'Delete', onconfirm: () => {} });

  async function loadAccounts() {
    accountsLoading = identities.length === 0;
    try {
      const [config, adminItems, userItems] = await Promise.all([
        adminApi.GET('/api/v1/admin/config'),
        fetchAllPages<AdminAccountResponse>((offset, limit) =>
          adminApi.GET('/api/v1/admin/admin-accounts', { params: { query: { offset, limit } } })),
        fetchAllPages<UserResponse>((offset, limit) =>
          adminApi.GET('/api/v1/admin/users', { params: { query: { offset, limit, kind: 'human' } } })),
      ]);
      if (config.data) authMode = config.data.auth_mode;
      const byEmail = new Map<string, Identity>();
      const get = (email: string): Identity => {
        let id = byEmail.get(email);
        if (!id) { id = { email }; byEmail.set(email, id); }
        return id;
      };
      for (const a of adminItems) {
        const id = get(a.email);
        if (a.display_name) id.displayName = a.display_name;
        id.console = { id: a.id, role: a.role, isActive: a.is_active };
      }
      for (const u of userItems) {
        const id = get(u.email);
        if (u.display_name) id.displayName = u.display_name;
        id.gateway = {
          id: u.id,
          isActive: u.is_active,
          workspaces: (u.workspaces ?? []).map((w) => ({
            workspace_id: w.workspace_id,
            workspace_name: w.workspace_name,
            role: w.role,
          })),
        };
      }
      identities = [...byEmail.values()].sort((a, b) => a.email.localeCompare(b.email));
      loadError = '';
    } catch (e: unknown) {
      loadError = e instanceof Error ? e.message : 'Failed to load accounts';
    } finally {
      accountsLoading = false;
    }
  }

  // ---- Access-level options (the unified ScopePicker vocabulary) ----
  const consoleOptions = $derived.by((): ScopeOption[] => {
    const hasConsole = modalMode === 'edit' && !!editing?.console;
    const none: ScopeOption = {
      value: 'none',
      label: 'No console access',
      description: hasConsole
        ? 'Removes console access on Save — the console account is permanently deleted.'
        : 'Cannot sign in to this admin console.',
    };
    if (isSystemTenant) {
      return [none, {
        value: 'granted',
        label: 'Super-admin',
        description: 'System-tenant console accounts manage the whole platform.',
      }];
    }
    if (isOidc) {
      return [none, {
        value: 'granted',
        label: 'Granted',
        description: 'Links on first OIDC login; the role (Admin / Read-only) comes from IdP groups.',
      }];
    }
    return [
      none,
      { value: 'read_only', label: 'Read-only', description: 'View everything; mutations are refused.' },
      { value: 'admin', label: 'Admin', description: 'Manage everything in this tenant.' },
    ];
  });

  const gatewayOptions = $derived.by((): ScopeOption[] => {
    const hasGateway = modalMode === 'edit' && !!editing?.gateway;
    return [
      {
        value: 'none',
        label: 'No gateway access',
        description: hasGateway
          ? 'Removes gateway access on Save — the user is deleted and all its keys are revoked.'
          : 'No portal sign-in, no API keys.',
      },
      {
        value: 'granted',
        label: 'Gateway user',
        description: 'Portal sign-in + API keys. Workspace membership and member/manager roles are managed on the workspace pages.',
      },
    ];
  });

  // ---- Open modal ----
  function openAdd() {
    modalMode = 'add';
    editing = null;
    formEmail = '';
    formDisplayName = '';
    formPassword = '';
    // Least-privilege defaults: gateway user is the common case; console is
    // opt-in. SYSTEM runs no gateway workloads, so console is the only grant.
    formConsole = isSystemTenant ? 'granted' : 'none';
    formGateway = isSystemTenant ? 'none' : 'granted';
    formError = '';
  }

  function openEdit(identity: Identity) {
    modalMode = 'edit';
    editing = identity;
    formEmail = identity.email;
    formDisplayName = identity.displayName ?? '';
    formPassword = '';
    formConsole = identity.console
      ? (isSystemTenant || isOidc ? 'granted' : identity.console.role)
      : 'none';
    formGateway = identity.gateway ? 'granted' : 'none';
    formError = '';
  }

  function closeModal() {
    modalMode = null;
    editing = null;
    dirty.markClean();
  }

  /** One explicit Save — applies profile changes, role changes, grants, AND
   *  removals (a "No access" pick deletes that capability) in merged per-plane
   *  requests. Removals preview their impact in a confirm step first. */
  async function saveIdentity() {
    if (modalMode === 'add' && !formEmail.trim()) {
      formError = 'Email is required.';
      return;
    }
    if (modalMode === 'add' && formConsole === 'none' && formGateway === 'none') {
      formError = 'Pick at least one access level.';
      return;
    }
    const removeConsole = !!editing?.console && formConsole === 'none';
    const removeGateway = !!editing?.gateway && formGateway === 'none';
    if (!removeConsole && !removeGateway) {
      await performSave(false, false);
      return;
    }

    // Preview the removal impact before applying anything.
    formBusy = true;
    let keys = 0;
    let sessions = 0;
    if (removeGateway) {
      const { data: impact, error: dryErr } = await adminApi.DELETE('/api/v1/admin/users/{id}', {
        params: { path: { id: editing!.gateway!.id }, query: { dry_run: true } },
      });
      if (dryErr) {
        formError = extractError(dryErr, 'Failed to preview impact');
        formBusy = false;
        return;
      }
      keys = impact?.affected_keys ?? 0;
      sessions = impact?.affected_oauth_sessions ?? 0;
    }
    formBusy = false;
    const parts = [
      removeConsole ? 'console access (the console account is permanently deleted)' : '',
      removeGateway ? 'gateway access (the user is deleted and its keys are revoked)' : '',
    ].filter(Boolean);
    impactModal = {
      open: true,
      title: 'Remove access?',
      message: `Saving removes ${parts.join(' and ')} for ${editing!.email}. This cannot be undone.`,
      affectedKeys: keys,
      affectedSessions: sessions,
      affectedUsers: removeGateway ? 1 : 0,
      confirmLabel: 'Remove & Save',
      onconfirm: async () => {
        impactModal.open = false;
        await performSave(removeConsole, removeGateway);
      },
    };
  }

  async function performSave(removeConsole: boolean, removeGateway: boolean) {
    formBusy = true;
    formError = '';
    const email = modalMode === 'add' ? formEmail.trim() : editing!.email;
    const password = !isOidc && formPassword ? formPassword : undefined;
    try {
      const hasConsole = !!editing?.console;
      const hasGateway = !!editing?.gateway;
      const nameChanged = formDisplayName !== (editing?.displayName ?? '');
      const consoleRole = formConsole === 'read_only' || formConsole === 'admin' ? formConsole : undefined;

      // Grants (new capability rows).
      if (!hasConsole && formConsole !== 'none') {
        const { error: err } = await adminApi.POST('/api/v1/admin/admin-accounts', {
          body: {
            email,
            display_name: formDisplayName || undefined,
            password,
            role: consoleRole,
          },
        });
        if (err) throw new Error(extractError(err, 'Failed to grant console access'));
      }
      if (!hasGateway && formGateway === 'granted') {
        const { error: err } = await adminApi.POST('/api/v1/admin/users', {
          body: { email, display_name: formDisplayName || undefined, password },
        });
        if (err) throw new Error(extractError(err, 'Failed to grant gateway access'));
      }

      // Updates on existing capability rows (merged: one request per plane).
      // Profile edits ride the plane that SURVIVES this Save — a plane being
      // removed below must not be the carrier, or the edit is silently lost.
      const gatewayKept = hasGateway && !removeGateway;
      const consoleKept = hasConsole && !removeConsole;
      if (gatewayKept && (nameChanged || password)) {
        const { error: err } = await adminApi.PATCH('/api/v1/admin/users/{id}', {
          params: { path: { id: editing!.gateway!.id } },
          body: {
            display_name: nameChanged ? formDisplayName || null : undefined,
            password,
          },
        });
        if (err) throw new Error(extractError(err, 'Failed to save'));
      }
      const roleChanged = hasConsole && !!consoleRole && consoleRole !== editing!.console!.role;
      if (consoleKept && (roleChanged || (!gatewayKept && (nameChanged || password)))) {
        const { error: err } = await adminApi.PATCH('/api/v1/admin/admin-accounts/{id}', {
          params: { path: { id: editing!.console!.id } },
          body: {
            display_name: !gatewayKept && nameChanged ? formDisplayName || null : undefined,
            password: gatewayKept ? undefined : password,
            role: roleChanged ? consoleRole : undefined,
          },
        });
        if (err) throw new Error(extractError(err, 'Failed to save'));
      }

      // Removals last — the profile edits above never target a deleted row.
      if (removeConsole) {
        const { error: err } = await adminApi.DELETE('/api/v1/admin/admin-accounts/{id}', {
          params: { path: { id: editing!.console!.id } },
        });
        if (err) throw new Error(extractError(err, 'Failed to remove console access'));
      }
      if (removeGateway) {
        const { error: err } = await adminApi.DELETE('/api/v1/admin/users/{id}', {
          params: { path: { id: editing!.gateway!.id } },
        });
        if (err) throw new Error(extractError(err, 'Failed to remove gateway access'));
      }

      if (modalMode === 'add' && formGateway === 'granted' && !isSystemTenant) {
        toast.success('Account created — add it to a workspace to enable key minting.');
      } else {
        toast.success('Saved');
      }
      closeModal();
      await loadAccounts();
    } catch (e: unknown) {
      formError = e instanceof Error ? e.message : 'Failed to save';
      // A multi-step Save can fail midway (e.g. console deleted, gateway
      // delete failed). Refresh the editing snapshot from the server so a
      // retry recomputes grants/removals against what actually exists.
      if (modalMode === 'edit' && editing) {
        await loadAccounts();
        editing = identities.find((i) => i.email === editing!.email) ?? editing;
      }
    } finally {
      formBusy = false;
    }
  }

  // ---- Capability actions (from the card list) ----
  // Disabling confirms (the gateway side stops the user's keys); enabling is
  // immediate. Busy is scoped per identity.
  function askToggle(identity: Identity, plane: 'console' | 'gateway') {
    const cap = plane === 'console' ? identity.console : identity.gateway;
    if (!cap) return;
    if (cap.isActive) {
      confirmDisable = { identity, plane };
    } else {
      void runToggle(identity, plane);
    }
  }

  async function runToggle(identity: Identity, plane: 'console' | 'gateway') {
    busyEmail = identity.email;
    try {
      const { error: err } =
        plane === 'console'
          ? await adminApi.PATCH('/api/v1/admin/admin-accounts/{id}', {
              params: { path: { id: identity.console!.id } },
              body: { is_active: !identity.console!.isActive },
            })
          : await adminApi.PATCH('/api/v1/admin/users/{id}', {
              params: { path: { id: identity.gateway!.id } },
              body: { is_active: !identity.gateway!.isActive },
            });
      if (err) toast.error(extractError(err, 'Failed to update account'));
      await loadAccounts();
    } finally {
      busyEmail = null;
    }
  }

  async function runConfirmedDisable() {
    const target = confirmDisable;
    confirmDisable = null;
    if (target) await runToggle(target.identity, target.plane);
  }

  usePeriodicLoad(loadAccounts, loadAccounts);
</script>

<div class="max-w-4xl">
  <div class="flex items-center justify-between mb-4">
    <p class="text-xs text-(--text-secondary)">
      {identities.length} {identities.length === 1 ? 'identity' : 'identities'} — console and gateway access per email
    </p>
    <button onclick={openAdd}
      class="px-4 py-2 bg-(--accent) hover:bg-(--accent-hover) rounded-lg text-(--accent-fg) text-sm font-medium transition-colors">
      + Add
    </button>
  </div>

  <div class="mb-4"><FormError message={loadError} /></div>

  {#if accountsLoading}
    <Skeleton variant="row" count={3} />
  {:else if identities.length === 0 && !loadError}
    <EmptyState title="No accounts" body="Add an account to grant console or gateway access." />
  {:else}
    <div class="bg-(--bg-card) rounded-xl border border-(--border) divide-y divide-(--border) overflow-hidden">
      {#each identities as identity (identity.email)}
        <IdentityCard
          {identity}
          busy={busyEmail === identity.email}
          onEdit={openEdit}
          onToggleConsole={(i) => askToggle(i, 'console')}
          onToggleGateway={(i) => askToggle(i, 'gateway')}
        />
      {/each}
    </div>
  {/if}
</div>

<!-- Add / Edit modal — profile + access levels (incl. removal via "No access"); Disable/Enable live on the cards -->
{#if modalMode}
  <Modal open={true} title={modalMode === 'add' ? 'Add Account' : `Edit ${editing?.email}`} onclose={closeModal} onCloseRequest={dirty.confirmDiscard}>
    <div class="space-y-4">
      <FormError message={formError} />

      {#if modalMode === 'add'}
        <div>
          <label for="acct-email" class="block text-sm font-medium text-(--text-secondary) mb-1.5">Email</label>
          <input id="acct-email" type="email" bind:value={formEmail} oninput={dirty.markDirty} placeholder="jane@acme.com"
            class="w-full px-3 py-2 rounded-lg bg-(--bg-primary) border border-(--border)
                   text-(--text-primary) text-sm focus:outline-hidden focus:border-(--accent)" />
        </div>
      {/if}

      <div>
        <label for="acct-display-name" class="block text-sm font-medium text-(--text-secondary) mb-1.5">Display Name</label>
        <input id="acct-display-name" type="text" bind:value={formDisplayName} oninput={dirty.markDirty} placeholder="Jane Smith"
          class="w-full px-3 py-2 rounded-lg bg-(--bg-primary) border border-(--border)
                 text-(--text-primary) text-sm focus:outline-hidden focus:border-(--accent)" />
      </div>

      {#if !isOidc}
        <div>
          <label for="acct-password" class="block text-sm font-medium text-(--text-secondary) mb-1.5">
            {modalMode === 'add' ? 'Password' : 'New Password'}
          </label>
          <input id="acct-password" type="password" bind:value={formPassword} oninput={dirty.markDirty}
            placeholder={modalMode === 'add' ? '••••••••' : 'leave empty to keep current'}
            class="w-full px-3 py-2 rounded-lg bg-(--bg-primary) border border-(--border)
                   text-(--text-primary) text-sm focus:outline-hidden focus:border-(--accent)" />
          <p class="text-xs text-(--text-secondary) mt-1">One password covers console and portal sign-in — set it once, it applies to both automatically.</p>
        </div>
      {:else}
        <p class="text-xs text-(--text-secondary)">Password is managed by the identity provider in OIDC mode.</p>
      {/if}

      <div oninput={dirty.markDirty}>
        <ScopePicker label="Console access" options={consoleOptions} bind:value={formConsole} />
      </div>
      {#if !isSystemTenant}
        <div oninput={dirty.markDirty}>
          <ScopePicker label="Gateway access" options={gatewayOptions} bind:value={formGateway} />
        </div>
      {:else}
        <p class="text-xs text-(--text-secondary)">The system tenant runs no gateway workloads — accounts here are console-only.</p>
      {/if}

      <div class="flex justify-end gap-3 pt-2">
        <button onclick={closeModal}
          class="px-4 py-2 rounded-lg border border-(--border) text-(--text-secondary) text-sm hover:bg-(--bg-elevated) transition-colors">Cancel</button>
        <button onclick={saveIdentity} disabled={formBusy || (modalMode === 'add' && !formEmail)}
          class="px-4 py-2 rounded-lg bg-(--accent) text-(--accent-fg) text-sm font-medium hover:bg-(--accent-hover) transition-colors disabled:opacity-50">
          {formBusy ? 'Saving…' : modalMode === 'add' ? 'Create' : 'Save'}
        </button>
      </div>
    </div>
  </Modal>
{/if}

<ConfirmDialog
  open={dirty.confirmOpen}
  title="Discard changes?"
  message="You have unsaved edits. Discard them?"
  confirmLabel="Discard"
  cancelLabel="Keep editing"
  destructive
  onconfirm={dirty.acceptDiscard}
  oncancel={dirty.rejectDiscard}
/>

<ConfirmDialog
  open={confirmDisable !== null}
  title={confirmDisable?.plane === 'gateway' ? 'Disable gateway access' : 'Disable console access'}
  message={confirmDisable
    ? confirmDisable.plane === 'gateway'
      ? `Disable gateway access for ${confirmDisable.identity.email}? Their API keys stop authenticating but are kept — enabling restores them.`
      : `Disable console access for ${confirmDisable.identity.email}? They can no longer sign in to this console until re-enabled.`
    : ''}
  confirmLabel="Disable"
  destructive
  onconfirm={runConfirmedDisable}
  oncancel={() => (confirmDisable = null)}
/>

<ImpactModal
  open={impactModal.open}
  title={impactModal.title}
  message={impactModal.message}
  affectedKeys={impactModal.affectedKeys}
  affectedUsers={impactModal.affectedUsers}
  affectedSessions={impactModal.affectedSessions}
  confirmLabel={impactModal.confirmLabel}
  onconfirm={impactModal.onconfirm}
  oncancel={() => impactModal.open = false}
/>
