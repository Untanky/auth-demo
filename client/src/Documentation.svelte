<script lang="ts">
import SvelteMarkdown from 'svelte-markdown';
import { html } from '../README.md';
</script>

<template>
  <SvelteMarkdown source={html} />
</template>
