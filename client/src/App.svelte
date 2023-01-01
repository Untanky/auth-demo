<script lang="ts">
  import { onMount } from "svelte";
  import Documentation from "./documentation/Documentation.svelte";
  import Navigation from "./navigation/Navigation.svelte";
  import SmartWebauthn from "./webauthn/SmartWebauthn.svelte";

  onMount(() => {
    console.log(window.location.pathname)
    if (window.location.pathname.startsWith("/finish")) {
      const code = new URLSearchParams(window.location.search).get('code');
      fetch(`http://localhost:8080/api/oauth2/v1/token?grant_type=authorization_code&code=${code}&client_id=abc`, { method: 'POST' })
    }
  })

  const onClick = () => {
    fetch(`http://localhost:8080/api/oauth2/v1/authorize?response_type=code&client_id=abc`, { redirect: 'follow' }).then((response) => {
      if (response.redirected) {
          window.location.href = response.url;
      }
    });
  }
</script>

<div class="max-w-[846px] m-4 md:mx-auto md:mt-16">
  <button on:click={onClick}>Start authorization</button>
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