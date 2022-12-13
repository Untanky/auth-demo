<script lang="ts">
  const goBack = () => {
    window.history.back();
  }
</script>

<template>
  <nav class="mb-4 flex flex-col items-start">
    <button class="button border-0 underline" on:keydown={goBack} on:click={goBack}>Back</button>
    <ul class="flex flex-row text-zinc-700 dark:text-zinc-300 rounded-xl border border-zinc-600 dark:border-zinc-400 max-w-full overflow-x-scroll">
      <li>
        <a class="block px-6 py-2.5 cursor-pointer text-amber-700">Description</a>
      </li>
      <li>
        <a class="block px-6 py-2.5 cursor-pointer">Implementation</a>
      </li>
      <li>
        <a class="block px-6 py-2.5 cursor-pointer" href="https://github.com/Untanky/webauthn">GitHub</a>
      </li>
    </ul>
  </nav>
</template>
