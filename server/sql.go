package main

import (
	"database/sql"
)

func ConnectDB() (*sql.DB, error) {
	db, err := sql.Open("sqlite3", "./foo.db")
	if err != nil {
		return nil, err
	}

	runMigration(
		db,
		`
		CREATE TABLE credential (
			id VARCHAR NOT NULL PRIMARY KEY,
			public_key BLOB NOT NULL,
			type VARCHAR,
			transports VARCHAR,
			user_id VARCHAR NOT NULL
		)
		`,
		"masterMigration",
	)

	return db, nil
}

func runMigration(db *sql.DB, sql string, identifier string) error {
	_, err := db.Exec(sql)
	if err != nil {
		return err
	}
	return nil
}
