package main

import (
	"database/sql"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"strconv"
	"time"

	"github.com/gorilla/mux"
	"github.com/gorilla/sessions"
	_ "github.com/lib/pq"
	"golang.org/x/crypto/bcrypt"
)

// Определяем структуры User, Chat и Message
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

var db *sql.DB
var store = sessions.NewCookieStore([]byte("secret-key"))

func createTable() {
	// Очищаем таблицы
	_, err := db.Exec("TRUNCATE TABLE messages, chat_users, chats, users RESTART IDENTITY CASCADE;")
	if err != nil {
		log.Fatal(err)
	}

	// Создаем таблицы
	_, err = db.Exec(`
	CREATE TABLE IF NOT EXISTS users (
		id SERIAL PRIMARY KEY,
		username TEXT NOT NULL UNIQUE,
		name TEXT NOT NULL,
		surname TEXT NOT NULL,
		patronymic TEXT NOT NULL,
		password TEXT NOT NULL,
		status TEXT NOT NULL DEFAULT 'offline',
		last_active TIMESTAMP DEFAULT CURRENT_TIMESTAMP
	);`)
	if err != nil {
		log.Fatal(err)
	}

	_, err = db.Exec(`
	CREATE TABLE IF NOT EXISTS chats (
		id SERIAL PRIMARY KEY,
		name TEXT NOT NULL,
		is_private BOOLEAN NOT NULL,
		creator_id INT REFERENCES users(id),
		created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
	);`)
	if err != nil {
		log.Fatal(err)
	}

	_, err = db.Exec(`
	CREATE TABLE IF NOT EXISTS messages (
		id SERIAL PRIMARY KEY,
		chat_id INT REFERENCES chats(id),
		user_id INT REFERENCES users(id),
		content TEXT NOT NULL,
		created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
	);`)
	if err != nil {
		log.Fatal(err)
	}

	_, err = db.Exec(`
	CREATE TABLE IF NOT EXISTS chat_users (
		chat_id INT REFERENCES chats(id),
		user_id INT REFERENCES users(id),
		PRIMARY KEY (chat_id, user_id)
	);`)
	if err != nil {
		log.Fatal(err)
	}

	// Вставляем предсозданных пользователей
	predefinedUsers := []struct {
		username   string
		name       string
		surname    string
		patronymic string
		password   string
		status     string
	}{
		{"1", "1", "1", "1", "1", "offline"},
		{"2", "2", "2", "2", "2", "offline"},
		{"3", "3", "3", "3", "3", "offline"},
	}

	for _, user := range predefinedUsers {
		// Хешируем пароль
		hashedPassword, err := bcrypt.GenerateFromPassword([]byte(user.password), bcrypt.DefaultCost)
		if err != nil {
			log.Fatal(err)
		}

		_, err = db.Exec("INSERT INTO users (username, name, surname, patronymic, password, status) VALUES ($1, $2, $3, $4, $5, $6)",
			user.username, user.name, user.surname, user.patronymic, hashedPassword, user.status)
		if err != nil {
			log.Fatal(err)
		}
	}
}

func isAuthenticated(r *http.Request) bool {
	session, _ := store.Get(r, "session-name")
	_, ok := session.Values["username"].(string)
	return ok
}

func registerHandler(w http.ResponseWriter, r *http.Request) {
	if isAuthenticated(r) {
		http.Redirect(w, r, "/chats", http.StatusSeeOther)
		return
	}
	if r.Method == http.MethodPost {
		username := r.FormValue("username")
		name := r.FormValue("name")
		surname := r.FormValue("surname")
		patronymic := r.FormValue("patronymic")
		password := r.FormValue("password")

		hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
		if err != nil {
			http.Error(w, "Ошибка регистрации", http.StatusInternalServerError)
			return
		}

		_, err = db.Exec("INSERT INTO users (username, name, surname, patronymic, password, status) VALUES ($1, $2, $3, $4, $5, 'offline')", username, name, surname, patronymic, hashedPassword)
		if err != nil {
			http.Error(w, "Ошибка регистрации", http.StatusInternalServerError)
			return
		}

		session, _ := store.Get(r, "session-name")
		session.Values["username"] = username
		err = session.Save(r, w)
		if err != nil {
			http.Error(w, "Ошибка сохранения сессии", http.StatusInternalServerError)
			return
		}

		http.Redirect(w, r, "/chats", http.StatusSeeOther)
		return
	}
	tmpl := template.Must(template.ParseFiles("templates/register.html"))
	tmpl.Execute(w, nil)
}

func loginHandler(w http.ResponseWriter, r *http.Request) {
	if isAuthenticated(r) {
		http.Redirect(w, r, "/chats", http.StatusSeeOther)
		return
	}
	if r.Method == http.MethodPost {
		username := r.FormValue("username")
		password := r.FormValue("password")
		var dbPassword string
		err := db.QueryRow("SELECT password FROM users WHERE username = $1", username).Scan(&dbPassword)
		if err != nil {
			http.Error(w, "Неверные учетные данные", http.StatusUnauthorized)
			return
		}

		err = bcrypt.CompareHashAndPassword([]byte(dbPassword), []byte(password))
		if err != nil {
			http.Error(w, "Неверные учетные данные", http.StatusUnauthorized)
			return
		}

		session, _ := store.Get(r, "session-name")
		session.Values["username"] = username
		err = session.Save(r, w)
		if err != nil {
			http.Error(w, "Ошибка сохранения сессии", http.StatusInternalServerError)
			return
		}

		http.Redirect(w, r, "/chats", http.StatusSeeOther)
		return
	}
	tmpl := template.Must(template.ParseFiles("templates/login.html"))
	tmpl.Execute(w, nil)
}

func logoutHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Метод не разрешен", http.StatusMethodNotAllowed)
		return
	}

	session, _ := store.Get(r, "session-name")
	username, ok := session.Values["username"].(string)

	if !ok {
		http.Error(w, "Пользователь не авторизован", http.StatusUnauthorized)
		return
	}

	_, err := db.Exec("UPDATE users SET status = 'offline' WHERE username = $1", username)
	if err != nil {
		http.Error(w, "Ошибка обновления статуса", http.StatusInternalServerError)
		return
	}

	delete(session.Values, "username")
	session.Save(r, w)

	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

func chatsHandler(w http.ResponseWriter, r *http.Request) {
	if !isAuthenticated(r) {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}

	session, _ := store.Get(r, "session-name")
	username := session.Values["username"].(string)

	var userID int
	err := db.QueryRow("SELECT id FROM users WHERE username = $1", username).Scan(&userID)
	if err != nil {
		http.Error(w, "Ошибка получения пользователя", http.StatusInternalServerError)
		return
	}

	// Измените запрос, чтобы получить все чаты, в которых участвует пользователь
	rows, err := db.Query(`
		SELECT c.id, c.name, c.is_private 
		FROM chats c
		JOIN chat_users cu ON c.id = cu.chat_id
		WHERE cu.user_id = $1`, userID)
	if err != nil {
		http.Error(w, "Ошибка получения чатов", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var chats []Chat
	for rows.Next() {
		var chat Chat
		if err := rows.Scan(&chat.ID, &chat.Name, &chat.IsPrivate); err != nil {
			http.Error(w, "Ошибка получения данных", http.StatusInternalServerError)
			return
		}
		chats = append(chats, chat)
	}

	tmpl := template.Must(template.ParseFiles("templates/chats.html"))
	tmpl.Execute(w, struct {
		Username string
		Chats    []Chat
	}{Username: username, Chats: chats})
}

func createChatHandler(w http.ResponseWriter, r *http.Request) {
	if !isAuthenticated(r) {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}

	if r.Method == http.MethodPost {
		session, _ := store.Get(r, "session-name")
		username := session.Values["username"].(string)

		var userID int
		err := db.QueryRow("SELECT id FROM users WHERE username = $1", username).Scan(&userID)
		if err != nil {
			http.Error(w, "Ошибка получения пользователя", http.StatusInternalServerError)
			return
		}

		chatName := r.FormValue("chat_name")
		isPrivate := r.FormValue("is_private") == "on"

		// Создаем новый чат
		var chatID int
		err = db.QueryRow("INSERT INTO chats (name, is_private, creator_id) VALUES ($1, $2, $3) RETURNING id", chatName, isPrivate, userID).Scan(&chatID)
		if err != nil {
			http.Error(w, "Ошибка создания чата", http.StatusInternalServerError)
			return
		}

		// Добавляем пользователя в таблицу chat_users
		_, err = db.Exec("INSERT INTO chat_users (chat_id, user_id) VALUES ($1, $2)", chatID, userID)
		if err != nil {
			http.Error(w, "Ошибка добавления пользователя в чат", http.StatusInternalServerError)
			return
		}

		http.Redirect(w, r, "/chats", http.StatusSeeOther)
		return
	}

	tmpl := template.Must(template.ParseFiles("templates/create_chat.html"))
	tmpl.Execute(w, nil)
}

func chatHandler(w http.ResponseWriter, r *http.Request) {
	if !isAuthenticated(r) {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}

	chatID := mux.Vars(r)["id"]

	rows, err := db.Query("SELECT id, name, is_private FROM chats WHERE id = $1", chatID)
	if err != nil {
		http.Error(w, "Ошибка получения чата", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var chat Chat
	if rows.Next() {
		if err := rows.Scan(&chat.ID, &chat.Name, &chat.IsPrivate); err != nil {
			http.Error(w, "Ошибка получения данных", http.StatusInternalServerError)
			return
		}
	} else {
		http.NotFound(w, r)
		return
	}

	// Получаем сообщения чата
	messageRows, err := db.Query("SELECT m.id, m.user_id, m.content, m.created_at, u.username FROM messages m JOIN users u ON m.user_id = u.id WHERE chat_id = $1 ORDER BY m.created_at", chat.ID)
	if err != nil {
		http.Error(w, "Ошибка получения сообщений", http.StatusInternalServerError)
		return
	}
	defer messageRows.Close()

	var messages []Message
	for messageRows.Next() {
		var message Message
		if err := messageRows.Scan(&message.ID, &message.UserID, &message.Content, &message.CreatedAt, &message.Username); err != nil {
			http.Error(w, "Ошибка получения данных", http.StatusInternalServerError)
			return
		}
		messages = append(messages, message)
	}

	tmpl := template.Must(template.ParseFiles("templates/chat.html"))
	session, _ := store.Get(r, "session-name")
	username := session.Values["username"].(string)
	tmpl.Execute(w, struct {
		Chat     Chat
		Messages []Message
		Username string
	}{Chat: chat, Messages: messages, Username: username})
}

func sendMessageHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		chatID := r.FormValue("chat_id")
		session, _ := store.Get(r, "session-name")
		username := session.Values["username"].(string)

		var userID int
		err := db.QueryRow("SELECT id FROM users WHERE username = $1", username).Scan(&userID)
		if err != nil {
			http.Error(w, "Ошибка получения пользователя", http.StatusInternalServerError)
			return
		}

		content := r.FormValue("content")
		_, err = db.Exec("INSERT INTO messages (chat_id, user_id, content) VALUES ($1, $2, $3)", chatID, userID, content)
		if err != nil {
			http.Error(w, "Ошибка отправки сообщения", http.StatusInternalServerError)
			return
		}

		http.Redirect(w, r, fmt.Sprintf("/chat/%s", chatID), http.StatusSeeOther)
		return
	}
}

func addUserToChatHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		chatIDStr := r.FormValue("chat_id") // Получаем chat_id как строку
		userIDStr := r.FormValue("user_id") // Получаем user_id как строку

		// Преобразуем chatID и userID в int
		chatID, err := strconv.Atoi(chatIDStr)
		if err != nil {
			http.Error(w, "Неверный идентификатор чата", http.StatusBadRequest)
			return
		}

		userID, err := strconv.Atoi(userIDStr)
		if err != nil {
			http.Error(w, "Неверный идентификатор пользователя", http.StatusBadRequest)
			return
		}

		_, err = db.Exec("INSERT INTO chat_users (chat_id, user_id) VALUES ($1, $2)", chatID, userID)
		if err != nil {
			http.Error(w, "Ошибка добавления пользователя в чат", http.StatusInternalServerError)
			return
		}

		http.Redirect(w, r, fmt.Sprintf("/chat/%d", chatID), http.StatusSeeOther)
		return
	}
}

func addUserHandler(w http.ResponseWriter, r *http.Request) {
	if !isAuthenticated(r) {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}

	chatIDStr := mux.Vars(r)["id"]         // Get chat ID as a string
	chatID, err := strconv.Atoi(chatIDStr) // Convert to int
	if err != nil {
		http.Error(w, "Неверный идентификатор чата", http.StatusBadRequest)
		return
	}

	// Получаем всех пользователей
	rows, err := db.Query("SELECT id, username FROM users")
	if err != nil {
		http.Error(w, "Ошибка получения пользователей", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var users []User
	for rows.Next() {
		var user User
		if err := rows.Scan(&user.ID, &user.Username); err != nil {
			http.Error(w, "Ошибка получения данных", http.StatusInternalServerError)
			return
		}
		users = append(users, user)
	}

	tmpl := template.Must(template.ParseFiles("templates/add_user.html"))
	tmpl.Execute(w, struct {
		ChatID int
		Users  []User
	}{ChatID: chatID, Users: users}) // Pass chatID as int
}

func main() {
	var err error
	db, err = sql.Open("postgres", "user=admin password=admin dbname=chatdb sslmode=disable")
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	createTable()

	r := mux.NewRouter()
	r.HandleFunc("/", loginHandler).Methods("GET", "POST")
	r.HandleFunc("/register", registerHandler).Methods("GET", "POST")
	r.HandleFunc("/login", loginHandler).Methods("GET", "POST")
	r.HandleFunc("/chats", chatsHandler).Methods("GET")
	r.HandleFunc("/create_chat", createChatHandler).Methods("GET", "POST")
	r.HandleFunc("/chat/{id:[0-9]+}", chatHandler).Methods("GET")
	r.HandleFunc("/chat/{id:[0-9]+}/send", sendMessageHandler).Methods("POST")
	r.HandleFunc("/chat/{id:[0-9]+}/add_user", addUserHandler).Methods("GET")
	r.HandleFunc("/chat/{id:[0-9]+}/add_user", addUserToChatHandler).Methods("POST")
	r.HandleFunc("/logout", logoutHandler).Methods("POST")

	http.Handle("/", r)
	log.Println("Сервер запущен на http://localhost:8080")
	log.Fatal(http.ListenAndServe(":8080", nil))
}
