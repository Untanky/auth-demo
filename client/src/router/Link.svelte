<script lang="ts">
  import { history, isPathActive } from './history';
  export let path: string;

  const navigate = (e: Event) => {
    e.preventDefault();
    history.push(path)
  }
  const pathActive = isPathActive(path);
</script>

<template>
  <a href={path} class="router-link" class:active={$pathActive} on:click={navigate}>
    <slot></slot>
  </a>
</template>
