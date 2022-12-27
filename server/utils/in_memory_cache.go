package utils

import (
    "errors"
)

type InMemoryCache[value any] struct {
    Store map[string]value
    CreateEmpty CreateFunc[value]
}

func (cache *InMemoryCache[v]) Get(key string) (v, error) {
    val, ok := cache.Store[key]
    if !ok {
        return cache.CreateEmpty(), errors.New("could not find value with given key")
    }

    return val, nil
}

func (cache *InMemoryCache[v]) SetWithoutKey(value v) (string, error) {
    key := RandString(20)
    err := cache.Set(key, value)
    return key, err
}

func (cache *InMemoryCache[v]) Set(key string, value v) error {
    cache.Store[key] = value
    return nil
}

func (cache *InMemoryCache[v]) Delete(key string) error {
    delete(cache.Store, key)
    return nil
}
