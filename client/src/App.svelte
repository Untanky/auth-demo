<script lang="ts">
  import Card from "./Card.svelte";
  import Documentation from "./Documentation.svelte";
  import LoginForm from "./LoginForm.svelte";
  import Tailwind from "./Tailwind.svelte";
</script>

<main class="flex flex-row space-x-8 justify-center mt-16">
  <Card class="w-[600px]">
    <Documentation />
  </Card>
  <Card class="w-[300px]">
    <h1 class="text-3xl">Sign in</h1>
    <p class="pt-4">To authenticate You, please enter Your account identifier:</p>
    <LoginForm />
  </Card>
</main>
<Tailwind />