<script lang="ts">
import SvelteMarkdown from 'svelte-markdown';
import { html as description } from '../../DESCRIPTION.md';
import { html as documentation } from '../../README.md';
import Router from '../router/Router.svelte';
</script>

<template>
  <article class="prose prose-zinc dark:prose-invert prose-sm md:prose-base">
    <Router path="/">
      <SvelteMarkdown source={documentation} />
    </Router>
    <Router path="/description">
      <SvelteMarkdown source={description} />
    </Router>
  </article>
</template>
