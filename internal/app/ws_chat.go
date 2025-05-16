package app

import (
	"chat/internal/domain"
	"chat/internal/utils"
	"log"
	"net/http"
	"strconv"

	"github.com/gorilla/mux"
)

func (a *App) wsChatHandler(w http.ResponseWriter, r *http.Request) {
	chatID := mux.Vars(r)["id"]
	conn, err := a.upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Println("Ошибка при подключении WebSocket:", err)
		return
	}
	defer conn.Close()

	session, _ := a.memory.GetSession(r, "session-name")
	username := session.Values["username"].(string)

	userID, err := a.storage.GetUserIDByUsername(username)
	if err != nil {
		log.Println("Ошибка получения ID пользователя:", err)
		return
	}

	client := domain.Client{Conn: conn, UserID: userID, ChatID: utils.Atoi(chatID)}
	a.memory.AddClient(client)
	defer a.memory.DeleteClient(client)

	for {
		var msg domain.Message
		err := conn.ReadJSON(&msg)
		if err != nil {
			log.Println("Ошибка чтения сообщения:", err)
			break
		}
		msg.ChatID, _ = strconv.Atoi(chatID)
		msg.UserID = userID
		msg.Username = username

		// Шифруем сообщение перед сохранением
		encryptedContent, err := a.cipher.Encrypt(msg.Content)
		if err != nil {
			log.Println("Ошибка шифрования сообщения:", err)
			break
		}

		// Используем RETURNING для получения ID вставленного сообщения
		msg.Content = encryptedContent
		msg.ID, err = a.storage.InsertMessage(msg)
		if err != nil {
			log.Println("Ошибка сохранения сообщения:", err)
			break
		}

		// Отправляем сообщение всем клиентам в чате
		clients := a.memory.GetClientsByChatID(msg.ChatID)
		for _, client := range clients {
			// Дешифруем сообщение перед отправкой
			decryptedContent, err := a.cipher.Decrypt(encryptedContent)
			if err != nil {
				log.Println("Ошибка дешифрования сообщения:", err)
				break
			}

			msg.Content = decryptedContent
			if err := client.Conn.WriteJSON(msg); err != nil {
				log.Println("Ошибка отправки сообщения:", err)
				client.Conn.Close()
				a.memory.DeleteClient(client)
			}
		}
	}
}
