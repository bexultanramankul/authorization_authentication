package handlers

import (
	"authorization_authentication/internal/model"
	"authorization_authentication/internal/service"
	"encoding/json"
	"net/http"
)

type AuthHandler struct {
	authService *service.AuthService
}

type Response struct {
	Success bool        `json:"success"`
	Data    interface{} `json:"data,omitempty"`
	Error   string      `json:"error,omitempty"`
}

func NewAuthHandler(authService *service.AuthService) *AuthHandler {
	return &AuthHandler{authService: authService}
}

func (h *AuthHandler) Register(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	var req struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.sendErrorResponse(w, "Invalid request format", http.StatusBadRequest)
		return
	}

	user, err := h.authService.Register(r.Context(), req.Email, req.Password)
	if err != nil {
		status := http.StatusBadRequest
		if err == model.ErrUserAlreadyExists {
			status = http.StatusConflict
		}
		h.sendErrorResponse(w, err.Error(), status)
		return
	}

	h.sendSuccessResponse(w, user, http.StatusCreated)
}

func (h *AuthHandler) Login(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	var req struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.sendErrorResponse(w, "Invalid request format", http.StatusBadRequest)
		return
	}

	tokens, err := h.authService.Login(
		r.Context(),
		req.Email,
		req.Password,
		r.UserAgent(),
		r.RemoteAddr,
	)

	if err != nil {
		status := http.StatusUnauthorized
		if err == model.ErrUserNotFound {
			status = http.StatusNotFound
		}
		h.sendErrorResponse(w, err.Error(), status)
		return
	}

	h.sendSuccessResponse(w, tokens, http.StatusOK)
}

func (h *AuthHandler) Refresh(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	var req struct {
		RefreshToken string `json:"refresh_token"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.sendErrorResponse(w, "Invalid request format", http.StatusBadRequest)
		return
	}

	tokens, err := h.authService.RefreshTokens(r.Context(), req.RefreshToken)
	if err != nil {
		status := http.StatusUnauthorized
		if err == model.ErrSessionExpired {
			status = http.StatusForbidden
		}
		h.sendErrorResponse(w, err.Error(), status)
		return
	}

	h.sendSuccessResponse(w, tokens, http.StatusOK)
}

func (h *AuthHandler) Verify(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	var req struct {
		Token string `json:"token"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.sendErrorResponse(w, "Invalid request format", http.StatusBadRequest)
		return
	}

	claims, err := h.authService.VerifyToken(req.Token)
	if err != nil {
		h.sendErrorResponse(w, "Invalid token", http.StatusUnauthorized)
		return
	}

	h.sendSuccessResponse(w, claims, http.StatusOK)
}

func (h *AuthHandler) Logout(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	var req struct {
		RefreshToken string `json:"refresh_token"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.sendErrorResponse(w, "Invalid request format", http.StatusBadRequest)
		return
	}

	if err := h.authService.Logout(r.Context(), req.RefreshToken); err != nil {
		h.sendErrorResponse(w, err.Error(), http.StatusUnauthorized)
		return
	}

	h.sendSuccessResponse(w, nil, http.StatusOK)
}

// Вспомогательные методы для отправки ответов
func (h *AuthHandler) sendErrorResponse(w http.ResponseWriter, errorMsg string, statusCode int) {
	w.WriteHeader(statusCode)
	json.NewEncoder(w).Encode(Response{
		Success: false,
		Error:   errorMsg,
	})
}

func (h *AuthHandler) sendSuccessResponse(w http.ResponseWriter, data interface{}, statusCode int) {
	w.WriteHeader(statusCode)
	json.NewEncoder(w).Encode(Response{
		Success: true,
		Data:    data,
	})
}
