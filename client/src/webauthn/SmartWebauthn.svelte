<script lang="ts">
  import LoginForm from './LoginForm.svelte';
  import { authenticate } from './webauthn';

  let loggedIn = false;

  enum StorageKeys {
    AccessKey = 'accessKey'
  }

  const onAuthenticate = async (event: CustomEvent): Promise<void> => {
    try {
      const { accessKey } = await authenticate(event.detail);
      localStorage.setItem(StorageKeys.AccessKey, accessKey);
      loggedIn = true;
    } catch {
      localStorage.removeItem(StorageKeys.AccessKey)
    }
  }
</script>

<template>
{#if loggedIn === false}
  <div>
    <h1 class="text-lg font-semibold">Sign in</h1>
    <p class="pt-2 text-zinc-700 dark:text-zinc-300">To authenticate You, please enter Your account identifier.</p>
    <LoginForm on:authenticate={onAuthenticate}></LoginForm>
  </div>
{:else}
  <p>Successfully logged in</p>
{/if}
</template>
