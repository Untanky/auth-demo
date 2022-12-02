package main

import "fmt"

type Credential struct {
	Id         []byte
	PublicKey  PublicKey
	Type       string
	Transports []string
}

type User struct {
	Identifier  string
	Credentials []Credential
}

type UserRepository interface {
	FindByIdentifier(identifier string) (*User, error)
	Create(user *User) error
}

type InMemoryUserRepository struct {
	knownUsers []*User
}

func (repo *InMemoryUserRepository) FindByIdentifier(identifier string) (*User, error) {
	for i := 0; i < len(repo.knownUsers); i++ {
		if identifier == repo.knownUsers[i].Identifier {
			return repo.knownUsers[i], nil
		}
	}

	return nil, fmt.Errorf("No user with identifier '%s' found", identifier)
}

func (repo *InMemoryUserRepository) Create(user *User) error {
    repo.knownUsers = append(repo.knownUsers, user)
    fmt.Println(*user)
	return nil
}
