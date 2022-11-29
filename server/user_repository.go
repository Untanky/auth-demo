package main

import "fmt"

type User struct {
    Identifier string
}

type UserRepository interface {
    FindByIdentifier(identifier string) (*User, error)
    Create(user *User) error
}

type InMemoryUserRepository struct {
    knownUsers []string
}

func (repo *InMemoryUserRepository) FindByIdentifier(identifier string) (*User, error) {
    for i := 0; i < len(repo.knownUsers); i++ {
        if identifier == repo.knownUsers[i] {
            return &User {
                Identifier: identifier,
                }, nil
        }
    }

    return nil, fmt.Errorf("No user with identifier '%s' found", identifier)
}

func (repo *InMemoryUserRepository) Create(user *User) error {
    repo.knownUsers = append(repo.knownUsers, user.Identifier)
    return nil
}
