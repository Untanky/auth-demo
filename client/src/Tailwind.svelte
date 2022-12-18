<style global>
@tailwind base;
@tailwind components;
@tailwind utilities;


@layer base {
  body {
    @apply dark/:text-zinc-50 dark/:bg-zinc-900
  }
}

@layer components {
  .card {
    @apply p-6 rounded-xl border-2 border-zinc-400 dark/:border-zinc-600;
  }

  label {
    @apply text-zinc-500 dark/:border-zinc-600;
  }

  button, .button-sm, .button-md, .link-button-sm, .link-button-md {
    @apply border border-zinc-600 dark/:border-zinc-400 bg-transparent;
  }

  button, input, textarea, select .button-md, .link-button-md, .input-md {
    @apply px-6 py-2.5 rounded-xl;
  }

  input {
    @apply placeholder/:text-zinc-600 placeholder/:dark/:text-zinc-400 shadow-inner dark/:shadow-none dark/:border-zinc-400 dark/:border dark/:bg-zinc-900;
  }

  .button-sm, .link-button-sm, .input-sm {
    @apply px-3 py-px rounded-lg;
  }

  .link-button-sm, .link-button-md {
    @apply hover/:cursor-pointer;
  }
}
</style>
