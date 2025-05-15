package main

import (
	"database/sql"
	"html/template"
	"log"
	"net/http"

	"github.com/gorilla/mux"
	"github.com/gorilla/sessions"
	_ "github.com/lib/pq"
	"golang.org/x/crypto/bcrypt"
)

// Определяем структуру User
type User struct {
	ID         int
	Username   string
	Name       string
	Surname    string
	Patronymic string
	Password   string
	Status     string // Добавлено поле для статуса
}

var db *sql.DB
var store = sessions.NewCookieStore([]byte("secret-key")) // Замените "secret-key" на ваш секретный ключ

func createTable() {
	// Удаляем таблицу users, если она существует
	_, err := db.Exec("DROP TABLE IF EXISTS users;")
	if err != nil {
		log.Fatal(err)
	}

	// Создаем таблицу users
	query := `
    CREATE TABLE IF NOT EXISTS users (
        id SERIAL PRIMARY KEY,
        username TEXT NOT NULL UNIQUE,
        name TEXT NOT NULL,
        surname TEXT NOT NULL,
        patronymic TEXT NOT NULL,
        password TEXT NOT NULL,
        status TEXT NOT NULL DEFAULT 'offline' 
    );`
	_, err = db.Exec(query)
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
		http.Redirect(w, r, "/users", http.StatusSeeOther)
		return
	}
	if r.Method == http.MethodPost {
		username := r.FormValue("username")
		name := r.FormValue("name")
		surname := r.FormValue("surname")
		patronymic := r.FormValue("patronymic")
		password := r.FormValue("password")

		// Хешируем пароль
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

		// Обновляем статус пользователя на online
		_, err = db.Exec("UPDATE users SET status = 'online' WHERE username = $1", username)
		if err != nil {
			http.Error(w, "Ошибка обновления статуса", http.StatusInternalServerError)
			return
		}

		// Сохраняем имя пользователя в сессии после регистрации
		session, _ := store.Get(r, "session-name")
		session.Values["username"] = username
		session.Values["justRegistered"] = true // Устанавливаем флаг
		err = session.Save(r, w)                // Обработка ошибки сохранения сессии
		if err != nil {
			http.Error(w, "Ошибка сохранения сессии", http.StatusInternalServerError)
			return
		}

		http.Redirect(w, r, "/users", http.StatusSeeOther)
		return
	}
	tmpl := template.Must(template.ParseFiles("templates/register.html"))
	tmpl.Execute(w, nil)
}

func loginHandler(w http.ResponseWriter, r *http.Request) {
	if isAuthenticated(r) {
		http.Redirect(w, r, "/users", http.StatusSeeOther)
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

		// Сравниваем хешированный пароль с введенным
		err = bcrypt.CompareHashAndPassword([]byte(dbPassword), []byte(password))
		if err != nil {
			http.Error(w, "Неверные учетные данные", http.StatusUnauthorized)
			return
		}

		// Обновляем статус пользователя на online
		_, err = db.Exec("UPDATE users SET status = 'online' WHERE username = $1", username)
		if err != nil {
			http.Error(w, "Ошибка обновления статуса", http.StatusInternalServerError)
			return
		}

		// Сохраняем имя пользователя в сессии
		session, _ := store.Get(r, "session-name")
		session.Values["username"] = username
		session.Values["justLoggedIn"] = true // Устанавливаем флаг
		err = session.Save(r, w)              // Обработка ошибки сохранения сессии
		if err != nil {
			http.Error(w, "Ошибка сохранения сессии", http.StatusInternalServerError)
			return
		}

		http.Redirect(w, r, "/users", http.StatusSeeOther)
		return
	}
	tmpl := template.Must(template.ParseFiles("templates/login.html"))
	tmpl.Execute(w, nil)
}

func logoutHandler(w http.ResponseWriter, r *http.Request) {
	session, _ := store.Get(r, "session-name")
	username, ok := session.Values["username"].(string)

	if !ok {
		http.Error(w, "Пользователь не авторизован", http.StatusUnauthorized)
		return
	}

	// Обновляем статус пользователя на offline
	_, err := db.Exec("UPDATE users SET status = 'offline' WHERE username = $1", username)
	if err != nil {
		http.Error(w, "Ошибка обновления статуса", http.StatusInternalServerError)
		return
	}

	// Удаляем имя пользователя из сессии
	delete(session.Values, "username")
	session.Save(r, w)

	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

func usersHandler(w http.ResponseWriter, r *http.Request) {
	if !isAuthenticated(r) {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}

	// Получаем имя пользователя из сессии
	session, _ := store.Get(r, "session-name")
	username := session.Values["username"].(string)

	rows, err := db.Query("SELECT id, username, name, surname, patronymic, status FROM users")
	if err != nil {
		http.Error(w, "Ошибка получения пользователей", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var users []User
	for rows.Next() {
		var user User
		if err := rows.Scan(&user.ID, &user.Username, &user.Name, &user.Surname, &user.Patronymic, &user.Status); err != nil {
			http.Error(w, "Ошибка получения данных", http.StatusInternalServerError)
			return
		}
		users = append(users, user)
	}

	// Передаем имя пользователя в шаблон
	tmpl := template.Must(template.ParseFiles("templates/users.html"))
	tmpl.Execute(w, struct {
		Username string
		Users    []User
	}{Username: username, Users: users})
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
	r.HandleFunc("/", loginHandler).Methods("GET", "POST") // Обработчик для корневого URL
	r.HandleFunc("/register", registerHandler).Methods("GET", "POST")
	r.HandleFunc("/login", loginHandler).Methods("GET", "POST") // Обработчик для логина
	r.HandleFunc("/users", usersHandler).Methods("GET")
	r.HandleFunc("/logout", logoutHandler).Methods("POST") // Обработчик выхода

	http.Handle("/", r)
	log.Println("Сервер запущен на http://localhost:8080")
	log.Fatal(http.ListenAndServe(":8080", nil))
}
