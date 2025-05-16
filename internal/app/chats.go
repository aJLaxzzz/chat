package app

import (
	"chat/internal/config"
	"chat/internal/domain"
	"fmt"
	"html/template"
	"net/http"
	"path/filepath"
)

func (a *App) chatsHandler(w http.ResponseWriter, r *http.Request) {
	if !a.isAuthenticated(r) {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}

	session, _ := a.memory.GetSession(r, "session-name")
	username := session.Values["username"].(string)

	user, err := a.storage.GetUserByUsername(username)
	if err != nil {
		http.Error(w, "Ошибка получения пользователя", http.StatusInternalServerError)
		return
	}

	chats, err := a.storage.GetChatsByUserID(user.ID)
	if err != nil {
		http.Error(w, "Ошибка получения чатов", http.StatusInternalServerError)
		return
	}

	fullName := fmt.Sprintf("%s %s %s", user.Surname, user.Name, user.Patronymic)

	tmpl := template.Must(template.ParseFiles(filepath.Join(config.TemplatesDirPath, "chats.html")))
	tmpl.Execute(w, struct {
		FullName string
		Chats    []domain.Chat
	}{
		FullName: fullName,
		Chats:    chats,
	})
}
