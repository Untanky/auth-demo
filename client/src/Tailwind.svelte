<style global>

@tailwind base;
@tailwind components;
@tailwind utilities;

@layer components {
  .card {
    @apply p-4 rounded-lg border border-gray-700 
  }

  label {
    @apply font-thin uppercase;
  }

  button, .button-sm, .button-md, .link-button-sm, .link-button-md, input, .input-sm .input-md, textarea, select {
    @apply rounded border border-gray-700
  }

  button, input, textarea, select .button-md, .link-button-md, .input-md {
    @apply px-4 py-2
  }

  .button-sm, .link-button-sm, .input-sm {
    @apply px-4 py-1
  }

  .link-button-sm, .link-button-md {
    @apply hover:cursor-pointer;
  }
}

</style>
