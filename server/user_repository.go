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

func (user *User) AllowedCredentials() []AllowCredentialResponse {
	credentials := []AllowCredentialResponse{}
	for i := 0; i < len(user.Credentials); i++ {
		credentials = append(credentials, AllowCredentialResponse{
			Id:         user.Credentials[i].Id,
			Type:       user.Credentials[i].Type,
			Transports: user.Credentials[i].Transports,
		})
	}
	return credentials
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
	return nil
}
