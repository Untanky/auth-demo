<script lang="ts">
  let clazz: string;
  export { clazz as class}
</script>

<tempalte>
  <div class="{`p-4 rounded-lg border border-gray-700 ${clazz}`}">
    <slot />
  </div>
</tempalte>