package core

// Read from a data store
type ViewRepository[id comparable, value any] interface {
	// Read a value by id
	FindByID(id) (value, error)
}

// Read and write from and to a data source
type Repository[id comparable, value any] interface {
	ViewRepository[id, value]
	// Create an empty struct in the data store
	CreateEmpty() (value, error)
	// Create a given struct in the data store
	Create(value) error
	// Update a given struct in the data store.
	//
	// Returns error, if value does not exist.
	Update(value) error
	// Delete a given value from the data store
	Delete(value) error
	// Delete the at the given ID from the data store
	DeleteByID(id) error
}
