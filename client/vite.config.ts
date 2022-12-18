import postcss from './postcss.config.js';
import { Mode, plugin as markdown } from 'vite-plugin-markdown';
import { svelte } from '@sveltejs/vite-plugin-svelte'
import { defineConfig } from 'vite'

// https://vitejs.dev/config/
export default defineConfig({
  plugins: [svelte(), markdown({ mode: [Mode.HTML] })],
  css: {
    postcss
  }
})
