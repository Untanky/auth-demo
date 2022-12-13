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
{#if loggedIn}
  <LoginForm on:authenticate={onAuthenticate}></LoginForm>
{:else}
  <p>Successfully logged in</p>
{/if}
</template>
