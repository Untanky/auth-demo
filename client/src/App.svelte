<script lang="ts">
  import Documentation from "./Documentation.svelte";
  import LoginForm from "./LoginForm.svelte";
  import Navigation from "./Navigation.svelte";
  import Tailwind from "./Tailwind.svelte";
</script>

<div class="max-w-[900px] m-4 md:mx-auto md:mt-16">
  <Navigation />
  <main class="flex flex-col md:flex-row gap-8 mt-8">
    <div class="order-2 md:order-1 w-[550px]">
      <Documentation />
    </div>
    <section class="order-1 md:order-2 card md:max-w-[350px]">
      <h1 class="text-xl">Sign in</h1>
      <p class="pt-2 text-zinc-700">To authenticate You, please enter Your account identifier.</p>
      <LoginForm />
    </section>
  </main>
</div>
<Tailwind />