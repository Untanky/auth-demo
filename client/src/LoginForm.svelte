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
    <input id="accountId" type="text" class="mt-1" placeholder="abc@example.com" bind:value="{accountId}" />
    <button type="submit" class="self-end mt-4 bg-amber-300 border-amber-900 text-amber-900" on:click={signIn}>Sign in</button>
  </form>
</template>