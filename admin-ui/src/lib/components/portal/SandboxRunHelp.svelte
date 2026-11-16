<script lang="ts">
  // The portal Quickstart's reference for `ssai run`: its modes, what a run
  // reaches, the container's upkeep and the other options. Static text — no
  // workspace data. Examples name `<client>`, never a real client: one named
  // here may be disabled for the reader.
  import { m } from '#lib/paraglide/messages.js';

  type Row = { cmd?: string; text: string };
  type Section = { title: string; rows: Row[] };

  const sections: Section[] = [
    {
      title: m.portal_qs_run_help_modes(),
      rows: [
        { cmd: 'ssai run <client>', text: m.portal_qs_run_help_mode_default() },
        { cmd: 'ssai run <client> --sandbox docker', text: m.portal_qs_run_help_mode_docker() },
        { cmd: 'ssai run <client> --sandbox off', text: m.portal_qs_run_help_mode_off() },
      ],
    },
    {
      title: m.portal_qs_run_help_reach(),
      rows: [
        { text: m.portal_qs_run_help_reach_policy() },
        { cmd: 'ssai run <client> --network gateway', text: m.portal_qs_run_help_reach_gateway() },
        { text: m.portal_qs_run_help_reach_blocked() },
      ],
    },
    {
      title: m.portal_qs_run_help_container(),
      rows: [
        { cmd: 'ssai sandbox prepare <client>', text: m.portal_qs_run_help_prepare() },
        { cmd: 'ssai sandbox status', text: m.portal_qs_run_help_status() },
        { cmd: 'ssai sandbox prune --project', text: m.portal_qs_run_help_prune() },
      ],
    },
    {
      title: m.portal_qs_run_help_other(),
      rows: [
        { cmd: 'ssai run <client> -e KEY=VALUE', text: m.portal_qs_run_help_env() },
        { cmd: 'ssai run <client> --ca-file <file>', text: m.portal_qs_run_help_ca() },
        { cmd: 'ssai run <client> --host <gateway>', text: m.portal_qs_run_help_host() },
        { cmd: 'ssai run <client> -- <arguments>', text: m.portal_qs_run_help_args() },
      ],
    },
  ];
</script>

<details class="text-xs text-(--text-secondary)" data-testid="sandbox-run-help">
  <summary class="cursor-pointer hover:text-(--text-primary) select-none">{m.portal_qs_run_help_summary()}</summary>
  <div class="mt-2 space-y-3 pl-2 border-l-2 border-(--border)">
    <p>{m.portal_qs_run_help_intro()}</p>
    {#each sections as section, i (section.title)}
      <div class="space-y-1">
        <p class="font-semibold text-(--text-primary)">{i + 1}. {section.title}</p>
        <ul class="space-y-1">
          {#each section.rows as row (row.text)}
            <li>
              {#if row.cmd}<code class="font-mono text-(--text-primary)">{row.cmd}</code> — {/if}{row.text}
            </li>
          {/each}
        </ul>
      </div>
    {/each}
  </div>
</details>
