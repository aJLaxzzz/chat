package domain

import (
	"time"

	"github.com/gorilla/websocket"
)

type User struct {
	ID         int
	Username   string
	Name       string
	Surname    string
	Patronymic string
	Password   string
	Status     string
	LastActive time.Time
}

type Chat struct {
	ID        int
	Name      string
	IsPrivate bool
	CreatorID int
	CreatedAt time.Time
}

type Message struct {
	ID        int
	ChatID    int
	UserID    int
	Content   string
	CreatedAt time.Time
	Username  string // Добавлено поле для имени пользователя
}

type Client struct {
	Conn   *websocket.Conn
	UserID int
	ChatID int
}
