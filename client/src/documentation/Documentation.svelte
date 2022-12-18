<script lang="ts">
import SvelteMarkdown from 'svelte-markdown';
import { html } from '../../README.md';
</script>

<template>
  <article class="prose prose-zinc dark:prose-invert prose-sm md:prose-base">
    <SvelteMarkdown source={html} />
  </article>
</template>
