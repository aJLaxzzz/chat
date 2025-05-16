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
	"github.com/gorilla/websocket"
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

type Client struct {
	Conn   *websocket.Conn
	UserID int
	ChatID int
}

var db *sql.DB
var store = sessions.NewCookieStore([]byte("secret-key"))
var upgrader = websocket.Upgrader{
	CheckOrigin: func(r *http.Request) bool {
		return true
	},
}

var clients = make(map[*Client]bool)

func createTable() {
	// Очищаем таблицы

	// Создаем таблицы
	_, err := db.Exec(`
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
		// Хешируем пароль
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

	rows, err := db.Query(`
		SELECT c.id, 
		       CASE 
		           WHEN c.is_private THEN 
		               (SELECT username FROM users WHERE id != $1 AND id IN (SELECT user_id FROM chat_users WHERE chat_id = c.id))
		           ELSE 
		               c.name
		       END AS name,
		       c.is_private 
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

func chatHandler(w http.ResponseWriter, r *http.Request) {
	if !isAuthenticated(r) {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}

	chatID := mux.Vars(r)["id"]

	// Получаем информацию о чате
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

	// Получаем участников чата
	participantRows, err := db.Query("SELECT u.id, u.username FROM chat_users cu JOIN users u ON cu.user_id = u.id WHERE cu.chat_id = $1", chat.ID)
	if err != nil {
		http.Error(w, "Ошибка получения участников чата", http.StatusInternalServerError)
		return
	}
	defer participantRows.Close()

	var participants []User
	for participantRows.Next() {
		var participant User
		if err := participantRows.Scan(&participant.ID, &participant.Username); err != nil {
			http.Error(w, "Ошибка получения данных участников", http.StatusInternalServerError)
			return
		}
		participants = append(participants, participant)
	}

	// Получаем текущего пользователя
	session, _ := store.Get(r, "session-name")
	username := session.Values["username"].(string)

	var currentUserID int
	err = db.QueryRow("SELECT id FROM users WHERE username = $1", username).Scan(&currentUserID)
	if err != nil {
		http.Error(w, "Ошибка получения текущего пользователя", http.StatusInternalServerError)
		return
	}

	// Если чат личный, изменяем название на имя другого участника
	if chat.IsPrivate {
		for _, participant := range participants {
			if participant.ID != currentUserID {
				chat.Name = participant.Username // Устанавливаем имя другого участника как название чата
				break
			}
		}
	}

	tmpl := template.Must(template.ParseFiles("templates/chat.html"))
	tmpl.Execute(w, struct {
		Chat         Chat
		Messages     []Message
		Participants []User
		Username     string
	}{Chat: chat, Messages: messages, Participants: participants, Username: username})
}

func wsChatHandler(w http.ResponseWriter, r *http.Request) {
	chatID := mux.Vars(r)["id"]
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Println("Ошибка при подключении WebSocket:", err)
		return
	}
	defer conn.Close()

	session, _ := store.Get(r, "session-name")
	username := session.Values["username"].(string)

	var userID int
	err = db.QueryRow("SELECT id FROM users WHERE username = $1", username).Scan(&userID)
	if err != nil {
		log.Println("Ошибка получения ID пользователя:", err)
		return
	}

	// Создаем новый клиент и добавляем его в мапу
	client := &Client{Conn: conn, UserID: userID, ChatID: atoi(chatID)} // Преобразуем chatID в int
	clients[client] = true
	defer delete(clients, client)

	for {
		var msg Message
		err := conn.ReadJSON(&msg)
		if err != nil {
			log.Println("Ошибка чтения сообщения:", err)
			break
		}
		msg.ChatID, _ = strconv.Atoi(chatID) // Установите ID чата
		msg.UserID = userID                  // Установите ID пользователя
		msg.Username = username              // Установите имя пользователя

		// Сохраняем сообщение в базе данных
		_, err = db.Exec("INSERT INTO messages (chat_id, user_id, content) VALUES ($1, $2, $3)", msg.ChatID, msg.UserID, msg.Content)
		if err != nil {
			log.Println("Ошибка сохранения сообщения:", err)
			break
		}

		// Отправляем сообщение только участникам текущего чата
		for client := range clients {
			if client.ChatID == msg.ChatID { // Проверяем, что клиент находится в том же чате
				if err := client.Conn.WriteJSON(msg); err != nil {
					log.Println("Ошибка отправки сообщения:", err)
					client.Conn.Close()
					delete(clients, client)
				}
			}
		}
	}
}

func atoi(s string) int {
	i, _ := strconv.Atoi(s)
	return i
}

func createPrivateChatHandler(w http.ResponseWriter, r *http.Request) {
	if !isAuthenticated(r) {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}

	session, _ := store.Get(r, "session-name")
	username := session.Values["username"].(string) // Получаем имя пользователя из сессии

	if r.Method == http.MethodPost {
		var userID int
		err := db.QueryRow("SELECT id FROM users WHERE username = $1", username).Scan(&userID)
		if err != nil {
			http.Error(w, "Ошибка получения пользователя", http.StatusInternalServerError)
			return
		}

		userIDToAdd, err := strconv.Atoi(r.FormValue("user_id"))
		if err != nil {
			http.Error(w, "Ошибка получения ID пользователя", http.StatusBadRequest)
			return
		}

		// Проверяем, существует ли уже чат между этими пользователями
		var existingChatID int
		err = db.QueryRow(`
			SELECT c.id FROM chats c
			JOIN chat_users cu1 ON c.id = cu1.chat_id
			JOIN chat_users cu2 ON c.id = cu2.chat_id
			WHERE cu1.user_id = $1 AND cu2.user_id = $2 AND c.is_private = true
		`, userID, userIDToAdd).Scan(&existingChatID)

		if err == nil {
			// Чат уже существует
			http.Error(w, "Личный чат с этим пользователем уже существует", http.StatusConflict)
			return
		} else if err != sql.ErrNoRows {
			// Ошибка при выполнении запроса
			http.Error(w, "Ошибка проверки существующих чатов", http.StatusInternalServerError)
			return
		}

		// Получаем ФИО второго пользователя
		var name, surname string
		err = db.QueryRow("SELECT name, surname FROM users WHERE id = $1", userIDToAdd).Scan(&name, &surname)
		if err != nil {
			http.Error(w, "Ошибка получения данных собеседника", http.StatusInternalServerError)
			return
		}

		// Название чата будет ФИО собеседника
		chatName := fmt.Sprintf("%s %s", name, surname)

		// Создаем новый личный чат
		var chatID int
		err = db.QueryRow("INSERT INTO chats (name, is_private, creator_id) VALUES ($1, $2, $3) RETURNING id", chatName, true, userID).Scan(&chatID)
		if err != nil {
			http.Error(w, "Ошибка создания чата", http.StatusInternalServerError)
			return
		}

		// Добавляем создателя и другого пользователя в таблицу chat_users
		_, err = db.Exec("INSERT INTO chat_users (chat_id, user_id) VALUES ($1, $2), ($1, $3)", chatID, userID, userIDToAdd)
		if err != nil {
			http.Error(w, "Ошибка добавления пользователей в чат", http.StatusInternalServerError)
			return
		}

		http.Redirect(w, r, "/chats", http.StatusSeeOther)
		return
	}

	// Получаем всех пользователей для выбора, исключая текущего пользователя
	rows, err := db.Query("SELECT id, username FROM users WHERE id != (SELECT id FROM users WHERE username = $1)", username)
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

	tmpl := template.Must(template.ParseFiles("templates/create_private_chat.html"))
	tmpl.Execute(w, struct {
		Users []User
	}{Users: users})
}

func createGroupChatHandler(w http.ResponseWriter, r *http.Request) {
	if !isAuthenticated(r) {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}

	session, _ := store.Get(r, "session-name")
	username := session.Values["username"].(string)

	var currentUserID int
	err := db.QueryRow("SELECT id FROM users WHERE username = $1", username).Scan(&currentUserID)
	if err != nil {
		http.Error(w, "Ошибка получения пользователя", http.StatusInternalServerError)
		return
	}

	if r.Method == http.MethodPost {
		chatName := r.FormValue("chat_name")
		isPrivate := false // Групповой чат не может быть личным

		// Создаем новый групповой чат
		var chatID int
		err = db.QueryRow("INSERT INTO chats (name, is_private, creator_id) VALUES ($1, $2, $3) RETURNING id", chatName, isPrivate, currentUserID).Scan(&chatID)
		if err != nil {
			http.Error(w, "Ошибка создания чата", http.StatusInternalServerError)
			return
		}

		// Добавляем создателя в таблицу chat_users
		_, err = db.Exec("INSERT INTO chat_users (chat_id, user_id) VALUES ($1, $2)", chatID, currentUserID)
		if err != nil {
			http.Error(w, "Ошибка добавления пользователя в чат", http.StatusInternalServerError)
			return
		}

		// Если это групповой чат, добавляем всех выбранных пользователей
		userIDs := r.Form["user_ids"] // Получаем массив ID пользователей
		for _, userIDToAddStr := range userIDs {
			userIDToAdd, err := strconv.Atoi(userIDToAddStr)
			if err != nil {
				http.Error(w, "Ошибка получения ID пользователя", http.StatusBadRequest)
				return
			}
			_, err = db.Exec("INSERT INTO chat_users (chat_id, user_id) VALUES ($1, $2)", chatID, userIDToAdd)
			if err != nil {
				http.Error(w, "Ошибка добавления пользователя в чат", http.StatusInternalServerError)
				return
			}
		}

		// Перенаправляем пользователя на страницу со списком чатов
		http.Redirect(w, r, "/chats", http.StatusSeeOther)
		return
	}

	// Получаем всех пользователей для выбора, исключая текущего пользователя
	rows, err := db.Query("SELECT id, username FROM users WHERE id != (SELECT id FROM users WHERE username = $1)", username)
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

	tmpl := template.Must(template.ParseFiles("templates/create_group_chat.html"))
	tmpl.Execute(w, struct {
		Users []User
	}{Users: users})
}

func editMessageHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Метод не разрешен", http.StatusMethodNotAllowed)
		return
	}

	messageID := r.FormValue("message_id")
	newContent := r.FormValue("content")
	chatID := r.FormValue("chat_id") // Получаем chatID из запроса

	// Обновляем сообщение в базе данных
	_, err := db.Exec("UPDATE messages SET content = $1 WHERE id = $2", newContent, messageID)
	if err != nil {
		http.Error(w, "Ошибка редактирования сообщения", http.StatusInternalServerError)
		return
	}

	// Отправляем уведомление всем клиентам
	for client := range clients {
		if client.ChatID == atoi(chatID) { // Преобразуем chatID в int
			err := client.Conn.WriteJSON(map[string]interface{}{
				"action":  "edit",
				"id":      messageID,
				"content": newContent,
			})
			if err != nil {
				log.Println("Ошибка отправки уведомления об редактировании:", err)
				client.Conn.Close()
				delete(clients, client)
			}
		}
	}
}

func deleteMessageHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Метод не разрешен", http.StatusMethodNotAllowed)
		return
	}

	messageID := r.FormValue("message_id")
	chatID := r.FormValue("chat_id") // Получаем chatID из запроса

	// Удаляем сообщение из базы данных
	_, err := db.Exec("DELETE FROM messages WHERE id = $1", messageID)
	if err != nil {
		http.Error(w, "Ошибка удаления сообщения", http.StatusInternalServerError)
		return
	}

	// Отправляем уведомление всем клиентам
	for client := range clients {
		if client.ChatID == atoi(chatID) { // Преобразуем chatID в int
			err := client.Conn.WriteJSON(map[string]interface{}{
				"action": "delete",
				"id":     messageID,
			})
			if err != nil {
				log.Println("Ошибка отправки уведомления об удалении:", err)
				client.Conn.Close()
				delete(clients, client)
			}
		}
	}
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
	r.HandleFunc("/chat/{id:[0-9]+}", chatHandler).Methods("GET")
	r.HandleFunc("/ws/chat/{id:[0-9]+}", wsChatHandler) // Обработчик WebSocket
	r.HandleFunc("/logout", logoutHandler).Methods("POST")

	r.HandleFunc("/create_private_chat", createPrivateChatHandler).Methods("GET", "POST")
	r.HandleFunc("/create_group_chat", createGroupChatHandler).Methods("GET", "POST")

	r.HandleFunc("/edit-message", editMessageHandler).Methods("POST")
	r.HandleFunc("/delete-message", deleteMessageHandler).Methods("POST")

	http.Handle("/", r)
	log.Println("Сервер запущен на http://localhost:8080")
	log.Fatal(http.ListenAndServe(":8080", nil))
}
