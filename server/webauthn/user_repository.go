package webauthn

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
	KnownUsers []*User
}

func (repo *InMemoryUserRepository) FindByIdentifier(identifier string) (*User, error) {
	for i := 0; i < len(repo.KnownUsers); i++ {
		if identifier == repo.KnownUsers[i].Identifier {
			return repo.KnownUsers[i], nil
		}
	}

	return nil, fmt.Errorf("No user with identifier '%s' found", identifier)
}

func (repo *InMemoryUserRepository) Create(user *User) error {
	repo.KnownUsers = append(repo.KnownUsers, user)
	return nil
}
