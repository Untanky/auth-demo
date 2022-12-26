package utils

import "errors"

type IDFunc[id comparable, value any] func(value) id

type CreateFunc[id comparable, value any] func() value

type InMemoryRepository[id comparable, value *any] struct {
    Store []value
    IdFunc IDFunc[id, value]
    CreateFunc CreateFunc[id, value]
}

func (repo *InMemoryRepository[i, v]) FindByID(id i) (v, error) {
    for i := 0; i < len(repo.Store); i++ {
        if id == repo.IdFunc(repo.Store[i]) {
            return repo.Store[i], nil
        }
    }

    return nil, errors.New("not found")
}

func (repo *InMemoryRepository[i, v]) CreateEmpty() (v, error) {
    newEntry := repo.CreateFunc()
    err := repo.Create(newEntry)
    return newEntry, err
}

func (repo *InMemoryRepository[i, v]) Create(value v) error {
    repo.Store = append(repo.Store, value)
    return nil
}

func (repo *InMemoryRepository[i, v]) Update(value v) error {
    repo.Store = append(repo.Store, value)
    return nil
}

func (repo *InMemoryRepository[i, v]) Delete(value v) error {
    return repo.DeleteByKey(repo.IdFunc(value))
}

func (repo *InMemoryRepository[i, v]) DeleteByKey(id i) error {
    for i := 0; i < len(repo.Store); i++ {
        if id == repo.IdFunc(repo.Store[i]) {
            repo.Store = append(repo.Store[:i], repo.Store[i+1:]...)
            return nil
        }
    }
}
