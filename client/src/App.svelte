<script lang="ts">
  import Documentation from "./Documentation.svelte";
  import LoginForm from "./LoginForm.svelte";
  import Navigation from "./Navigation.svelte";
  import Tailwind from "./Tailwind.svelte";
</script>

<main class="flex flex-row space-x-8 justify-center mt-16">
  <div>
    <Navigation />
    <section class="card w-[600px]">
      <Documentation />
    </section>
  </div>
  <section class="card w-[300px]">
    <h1 class="text-3xl">Sign in</h1>
    <p class="pt-4">To authenticate You, please enter Your account identifier.</p>
    <LoginForm />
  </section>
</main>
<Tailwind />