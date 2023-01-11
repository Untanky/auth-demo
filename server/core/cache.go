package core

// Read data from a key-value store
type ReadCache[key comparable, value any] interface {
	Get(key) (value, error)
}

// Write data from to a key-value store
type WriteCache[key comparable, value any] interface {
	// Set value and generate a new key
	SetWithoutKey(value) (key, error)
	// Set value with the specified key
	Set(key, value) error
	// Delete value at the specified key
	Delete(key) error
}

// Read and write data from and to a key-value store
type Cache[key comparable, value any] interface {
	ReadCache[key, value]
	WriteCache[key, value]
}
