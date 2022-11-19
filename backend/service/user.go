package service

type User struct {
	Id    int64  `json"id`
	Email string `json:"email"`
}

type UserService interface {
	SignUp(email string, password string) (*int64, *string, *string, error)
	SignIn(email string, password string) (*int64, *string, *string, error)
}
