package main

import (
	"database/sql"
	"fmt"
	"strings"

	"github.com/fxamacker/cbor"
)

type SqliteUserRepository struct {
	db *sql.DB
}

func (repo *SqliteUserRepository) FindByIdentifier(identifier string) (*User, error) {
	rows, err := repo.db.Query("SELECT id, public_key, type, transports FROM crendetial WHERE user_id = ?", identifier)
	if err != nil {
		return nil, fmt.Errorf("No user with identifier '%s' found", identifier)
	}
	defer rows.Close()

	crendentials := []Credential{}
	for rows.Next() {
		credential := Credential{}
		publicKey := []byte{}
		transports := []string{}
		rows.Scan(&credential.Id, &publicKey, &credential.Type, &transports)
		fmt.Println(publicKey)

		crendentials = append(crendentials, credential)
	}

	if len(crendentials) == 0 {
		return nil, fmt.Errorf("No user with identifier '%s' found", identifier)
	}

	user := &User{
		Identifier:  identifier,
		Credentials: crendentials,
	}
	fmt.Println(user)

	return user, nil
}

func (repo *SqliteUserRepository) Create(user *User) error {
	publicKey, err := cbor.Marshal(user.Credentials[0].PublicKey, cbor.CTAP2EncOptions())
	fmt.Println(publicKey, err)
	transports := strings.Join(user.Credentials[0].Transports, ",")

	_, err = repo.db.Exec(
		"INSERT INTO crendential (id, public_key, type, transports, user_id) VALUES (?, ?, ?, ?, ?)",
		user.Credentials[0].Id,
		publicKey,
		user.Credentials[0].Type,
		transports,
		user.Identifier,
	)
	if err != nil {
		fmt.Println(err)
		return fmt.Errorf("Could not insert with identifier '%s'", user.Identifier)
	}
	return nil
}
