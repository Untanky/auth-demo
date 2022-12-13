<script lang="ts">
  import Documentation from "./Documentation.svelte";
  import LoginForm from "./LoginForm.svelte";
  import Navigation from "./Navigation.svelte";
  import Tailwind from "./Tailwind.svelte";
</script>

<div class="max-w-[846px] m-4 md:mx-auto md:mt-16">
  <main class="grid md:grid-cols-[1fr_364px] md:flex-row gap-8">
    <div class="md:col-start-1 md:col-end-1 md:row-start-1">
      <Navigation />
    </div>
    <section class="md:col-start-1 md:col-end-1 md:row-start-2">
      <Documentation />
    </section>
    <section class="card md:col-start-2 md:col-end-2 md:row-start-2">
      <h1 class="text-xl">Sign in</h1>
      <p class="pt-2 text-zinc-700 dark:text-zinc-300">To authenticate You, please enter Your account identifier.</p>
      <LoginForm />
    </section>
  </main>
</div>
<Tailwind />