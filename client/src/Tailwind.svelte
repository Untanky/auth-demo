<style global>

@tailwind base;
@tailwind components;
@tailwind utilities;

@layer components {
  .card {
    @apply p-6 rounded-xl border border-zinc-600 
  }

  label {
    @apply text-zinc-400;
  }

  button, .button-sm, .button-md, .link-button-sm, .link-button-md, input, .input-sm .input-md, textarea, select {
    @apply border border-zinc-600
  }

  button, input, textarea, select .button-md, .link-button-md, .input-md {
    @apply px-6 py-2.5 rounded-xl 
  }

  input {
    @apply placeholder:text-zinc-600
  }

  .button-sm, .link-button-sm, .input-sm {
    @apply px-3 py-px rounded-lg
  }

  .link-button-sm, .link-button-md {
    @apply hover:cursor-pointer;
  }
}

</style>
