package app

import (
	"chat/internal/config"
	"html/template"
	"net/http"
	"path/filepath"

	"golang.org/x/crypto/bcrypt"
)

func (a *App) loginHandler(w http.ResponseWriter, r *http.Request) {
	if a.isAuthenticated(r) {
		http.Redirect(w, r, "/chats", http.StatusSeeOther)
		return
	}
	if r.Method == http.MethodPost {
		username := r.FormValue("username")
		password := r.FormValue("password")

		user, err := a.storage.GetUserByUsername(username)
		if err != nil {
			http.Error(w, "Неверные учетные данные", http.StatusUnauthorized)
			return
		}

		err = bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(password))
		if err != nil {
			http.Error(w, "Неверные учетные данные", http.StatusUnauthorized)
			return
		}

		session, _ := a.memory.GetSession(r, "session-name")
		session.Values["username"] = username
		err = session.Save(r, w)
		if err != nil {
			http.Error(w, "Ошибка сохранения сессии", http.StatusInternalServerError)
			return
		}

		err = a.storage.UpdateUserStatus(username, "online")
		if err != nil {
			http.Error(w, "Ошибка обновления статуса", http.StatusInternalServerError)
			return
		}

		http.Redirect(w, r, "/chats", http.StatusSeeOther)
		return
	}
	tmpl := template.Must(template.ParseFiles(filepath.Join(config.TemplatesDirPath, "login.html")))
	tmpl.Execute(w, nil)
}
