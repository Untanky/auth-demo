package utils

type ReadCache[key comparable, value any] interface {
	Get(key) (value, error)
}

type WriteCache[key comparable, value any] interface {
	SetWithoutKey(value) (key, error)
	SetKey(key, value) error
	Delete(key) error
}

type Cache[key comparable, value any] interface {
	ReadCache[key, value]
	WriteCache[key, value]
}
