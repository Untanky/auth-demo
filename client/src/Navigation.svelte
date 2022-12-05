<script lang="ts">
  const goBack = () => {
    window.history.back();
  }
</script>

<template>
  <nav class="mb-4 space-y-4">
    <ul>
      <li>
        <button class="button-sm" on:keydown={goBack} on:click={goBack}>Back</button>
      </li>
    </ul>
    <ul class="flex flex-row space-x-4">
      <li>
        <a class="link-button-md">Description</a>
      </li>
      <li>
        <a class="link-button-md" href="https://github.com/Untanky/webauthn">GitHub</a>
      </li>
    </ul>
  </nav>
</template>
