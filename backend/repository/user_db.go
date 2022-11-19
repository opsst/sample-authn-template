package repository

import (
	"database/sql"
	"fmt"
)

type UserRepositoryDB struct {
	db *sql.DB
}

func NewUserRepositoryDB(db *sql.DB) UserRepositoryDB {
	return UserRepositoryDB{db: db}
}

func (u UserRepositoryDB) CreateUser(email string, password string, secret string) (*User, error) {
	insert, err := u.db.Exec("INSERT INTO users (email, password, secret) VALUES (?,?,?) , email, password, secret")
	if err != nil {
		return nil, err
	}
	userId, err := insert.LastInsertId()

	var user = User{
		Id:       userId,
		Email:    email,
		Password: password,
		Secret:   secret,
	}
	return &user, nil
}

func (r UserRepositoryDB) CheckUser(email string) (*User, error) {
	fmt.Println("CheckUsr")
	return nil, nil
}
