package main

import (
    "encoding/base64"
    "encoding/json"
    "fmt"
    "net/http"
    "os"
    "time"

    "github.com/golang-jwt/jwt/v4"
    "golang.org/x/crypto/bcrypt"
)

var jwtSecret = []byte("supersecretkey") // Используйте переменные окружения в реальных приложениях
var refreshTokens = make(map[string]string) // Хранение Refresh токенов в памяти

// Структура для ответа с токенами
type TokenResponse struct {
    AccessToken  string `json:"access_token"`
    RefreshToken string `json:"refresh_token"`
}

// Структура для полезной нагрузки токена
type Claims struct {
    UserID string `json:"user_id"`
    IP     string `json:"ip"`
    jwt.RegisteredClaims
}

// Генерация Access и Refresh токенов
func generateTokens(userID, clientIP string) (string, string, error) {
    // Создание Access токена
    claims := Claims{
        UserID: userID,
        IP:     clientIP,
        RegisteredClaims: jwt.RegisteredClaims{
            ExpiresAt: jwt.NewNumericDate(time.Now().Add(15 * time.Minute)),
        },
    }
    token := jwt.NewWithClaims(jwt.SigningMethodHS512, claims)
    signedToken, err := token.SignedString(jwtSecret)
    if err != nil {
        return "", "", err
    }

    // Генерация Refresh токена
    rawRefreshToken := fmt.Sprintf("%s:%s", userID, time.Now().String())
    refreshToken := base64.StdEncoding.EncodeToString([]byte(rawRefreshToken))

    // Хеширование Refresh токена перед сохранением
    hashedRefreshToken, err := bcrypt.GenerateFromPassword([]byte(refreshToken), bcrypt.DefaultCost)
    if err != nil {
        return "", "", err
    }

    // Сохраняем хеши Refresh токенов
    refreshTokens[signedToken] = string(hashedRefreshToken)

    return signedToken, refreshToken, nil
}

// Обработчик запроса на получение токенов
func tokenHandler(w http.ResponseWriter, r *http.Request) {
    userID := r.URL.Query().Get("user_id")
    clientIP := r.RemoteAddr

    accessToken, refreshToken, err := generateTokens(userID, clientIP)
    if err != nil {
        http.Error(w, "Ошибка генерации токенов", http.StatusInternalServerError)
        return
    }

    response := TokenResponse{AccessToken: accessToken, RefreshToken: refreshToken}
    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(response)
}

// Обработчик запроса на обновление токенов
func refreshHandler(w http.ResponseWriter, r *http.Request) {
    var requestPayload struct {
        AccessToken  string `json:"access_token"`
        RefreshToken string `json:"refresh_token"`
    }

    if err := json.NewDecoder(r.Body).Decode(&requestPayload); err != nil {
        http.Error(w, "Неверный запрос", http.StatusBadRequest)
        return
    }

    // Проверка Access токена
    claims := &Claims{}
    token, err := jwt.ParseWithClaims(requestPayload.AccessToken, claims, func(token *jwt.Token) (interface{}, error) {
        return jwtSecret, nil
    })

    if err != nil || !token.Valid {
        http.Error(w, "Неверный Access токен", http.StatusUnauthorized)
        return
    }

    // Проверка Refresh токена
    hashedRefreshToken := refreshTokens[requestPayload.AccessToken]
    if err := bcrypt.CompareHashAndPassword([]byte(hashedRefreshToken), []byte(requestPayload.RefreshToken)); err != nil {
        http.Error(w, "Неверный Refresh токен", http.StatusUnauthorized)
        return
    }

    // Генерация новых токенов
    newAccessToken, newRefreshToken, err := generateTokens(claims.UserID, r.RemoteAddr)
    if err != nil {
        http.Error(w, "Ошибка генерации новых токенов", http.StatusInternalServerError)
        return
    }

    response := TokenResponse{AccessToken: newAccessToken, RefreshToken: newRefreshToken}
    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(response)
}

// Основная функция
func main() {
    http.HandleFunc("/token", tokenHandler)
    http.HandleFunc("/refresh", refreshHandler)

    port := "7030"
    fmt.Printf("Сервер запущен на порту %s...\n", port)
    if err := http.ListenAndServe(":"+port, nil); err != nil {
        fmt.Println(err)
        os.Exit(1)
    }
}
