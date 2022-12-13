<script lang="ts">
  let accountId: string;

  const signIn = (e: Event) => {
    e.preventDefault();
    console.log(accountId);
  }
</script>

<template>
  <form class="flex flex-col pt-4 ">
    <label for="accountId">Account ID:</label>
    <input id="accountId" type="text" class="mt-1 shadow-zinc-300" placeholder="abc@example.com" bind:value="{accountId}" />
    <button type="submit" class="self-end mt-4 bg-amber-300 dark:bg-amber-800 border-0 text-amber-700 dark:text-amber-200" on:click={signIn}>Sign in</button>
  </form>
</template>