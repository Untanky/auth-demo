<script lang="ts">
  const goBack = () => {
    window.history.back();
  }
</script>

<template>
  <nav class="mb-4 flex flex-col md:flex-row gap-2">
    <button class="button self-start" on:keydown={goBack} on:click={goBack}>Back</button>
    <ul class="flex flex-row text-zinc-700 rounded-xl border border-zinc-600 overflow-x-scroll">
      <li>
        <a class="block px-6 py-2.5 cursor-pointer text-black">Description</a>
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
