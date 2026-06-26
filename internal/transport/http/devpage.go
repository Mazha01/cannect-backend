package http

import (
	_ "embed"
	"net/http"
)

//go:embed assets/telegram_login.html
var telegramLoginPage []byte

// devTelegramLoginPage serves a self-contained HTML page that drives the full
// admin login flow (password → Telegram Login Widget → token) from the browser.
// Mounted only in development so it never ships to production.
func devTelegramLoginPage(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write(telegramLoginPage)
}
