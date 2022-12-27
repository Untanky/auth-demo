package utils

type ViewRepository[id comparable, value any] interface {
	FindByID(id) (value, error)
}

type Repository[id comparable, value any] interface {
	ViewRepository[id, value]
    CreateEmpty() (value, error)
	Create(value) error
	Update(value) error
	Delete(value) error
	DeleteByKey(id) error
}
