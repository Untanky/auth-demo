<script lang="ts">
  import Link from '../router/Link.svelte';
  import { history } from '../router/history';

  const goBack = () => {
    history.back();
  }
</script>

<template>
  <nav class="flex flex-col items-start space-y-4">
    <button class="border-0 p-0" on:click={goBack}>
      Back
    </button>
    <ul class="flex space-x-8">
      <li>
        <Link path="/">Documentation</Link>
      </li>
      <li>
        <Link path="/description">Description</Link>
      </li>
    </ul>
  </nav>
</template>
