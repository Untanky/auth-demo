<script lang="ts">
  import Documentation from "./documentation/Documentation.svelte";
  import Navigation from "./navigation/Navigation.svelte";
  import SmartWebauthn from "./webauthn/SmartWebauthn.svelte";
</script>

<div class="max-w-[846px] m-4 md:mx-auto md:mt-16">
  <main class="grid md:grid-cols-[1fr_364px] md:flex-row gap-8">
    <div class="row-start-2 md:col-start-1 md:col-end-1 md:row-start-1">
      <Navigation />
    </div>
    <section class="row-start-3 md:col-start-1 md:col-end-1 md:row-start-2">
      <Documentation />
    </section>
    <section class="card row-start-1 md:col-start-2 md:col-end-2 md:row-start-2 self-start sticky top-24">
      <SmartWebauthn />
    </section>
  </main>
</div>