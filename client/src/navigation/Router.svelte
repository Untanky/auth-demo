<script lang="ts">
  export let path: string;

  const urlPath = new URL(document.URL).pathname;
  console.log(path, urlPath);
</script>

<template>
  {#if path === urlPath}
    <slot></slot>
  {/if}
</template>