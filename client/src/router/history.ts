import { derived, readable, type Readable } from 'svelte/store';

class History {
  path: Readable<string>
  #pathSetter: (string) => void;

  constructor() {
    this.path = readable(null, set => {
	    set(new URL(document.URL).pathname);
      this.#pathSetter = set;

      return;
    });
  }

  push(path = '/') {
    window.history.pushState(null, '', path);
    this.#pathSetter(path);
  }

  back() {
    window.history.back();
    this.#pathSetter(new URL(document.URL).pathname);
  }
}

export const history = new History();

export const isPathActive = (desiredPath: string): Readable<boolean> => derived(history.path, (path, set) => set(path === desiredPath))

