<!--
  Three-letter ISO 4217 code entry. A free-text input rather than a closed
  select: the gateway prices against whatever a provider quotes, so the list
  below is a shortcut for the common codes, not the permitted set. Typed input
  is upper-cased and clamped to three letters as it is entered, so a code can
  only ever leave here in the canonical form the API matches on.
-->
<script lang="ts" module>
  /** Suggestion list only — any ISO 4217 code is accepted. */
  export const COMMON_CURRENCIES = [
    'USD', 'EUR', 'GBP', 'CHF', 'JPY', 'CNY', 'CAD', 'AUD', 'SEK', 'NOK',
    'DKK', 'PLN', 'INR', 'BRL', 'SGD', 'KRW', 'ILS', 'ZAR', 'AED', 'NZD',
  ];
</script>

<script lang="ts">
  import TextInput from '#lib/components/forms/TextInput.svelte';

  let {
    value = $bindable(''),
    id,
    disabled = false,
    placeholder = 'USD',
  }: {
    value?: string;
    id?: string;
    disabled?: boolean;
    placeholder?: string;
  } = $props();

  // Per-instance, because several of these render side by side (the conversion
  // table) and a shared `<datalist>` id would leave every input pointing at the
  // first one's element.
  const uid = $props.id();
  const listId = `iso4217-${uid}`;

  // Canonicalise on commit rather than per keystroke: rewriting the value on
  // every `input` event fights the same element's `bind:value` and moves the
  // caret mid-word. Every write path upper-cases again before it reaches the
  // API, so this is what the operator sees, not what the API relies on.
  function normalize(e: Event) {
    const el = e.currentTarget as HTMLInputElement;
    value = el.value.replace(/[^A-Za-z]/g, '').slice(0, 3).toUpperCase();
  }
</script>

<TextInput
  {id}
  {disabled}
  {placeholder}
  bind:value
  mono
  list={listId}
  maxlength={3}
  autocapitalize="characters"
  spellcheck={false}
  onchange={normalize}
/>
<datalist id={listId}>
  {#each COMMON_CURRENCIES as code (code)}
    <option value={code}></option>
  {/each}
</datalist>
