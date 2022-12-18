<script lang="ts">
  const goBack = () => {
    window.history.back();
  }
</script>

<template>
  <nav class="mb-4 flex flex-col items-start space-y-4">
    <button class="border-0 p-0">
      Back
    </button>
    <ul class="flex space-x-8">
      <li class="text-xl font-medium border-amber-600 border-b-[3px]">
        <a>Description</a>
      </li>
      <li class="text-xl font-medium cursor-pointer">
        <a>Documentation</a>
      </li>
    </ul>
  </nav>
</template>
