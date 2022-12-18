<script lang="ts">
  import { history, isPathActive } from './history';

  export let path: string;
  const pathActive = isPathActive(path);
</script>

<template>
  {#if $pathActive === true}
    <slot></slot>
  {/if}
</template>