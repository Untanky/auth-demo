<script lang="ts">
  let accountId: string;

  const signIn = (e: Event) => {
    e.preventDefault();
    console.log(accountId);
  }
</script>

<template>
  <form class="flex flex-col pt-4">
    <label for="accountId" class="">Account ID:</label>
    <input id="accountId" type="text" bind:value="{accountId}" />
    <button type="submit" class="mt-4 bg-orange-500 border-orange-700" on:click={signIn}>Sign in</button>
  </form>
</template>