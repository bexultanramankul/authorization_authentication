package util

import (
	"errors"
	"net"
)

var (
	ErrInvalidIP = errors.New("invalid IP address format")
)

// NormalizeIP проверяет и нормализует IP-адрес
func NormalizeIP(rawIP string) (string, error) {
	// Удаляем порт, если он есть
	host, _, err := net.SplitHostPort(rawIP)
	if err == nil {
		rawIP = host // Используем только IP-часть
	}

	// Проверяем валидность IP
	ip := net.ParseIP(rawIP)
	if ip == nil {
		return "", ErrInvalidIP
	}

	return ip.String(), nil
}

// NormalizeIPWithPort сохраняет порт, но валидирует IP
func NormalizeIPWithPort(rawIP string) (string, error) {
	host, port, err := net.SplitHostPort(rawIP)
	if err != nil {
		// Если это IP без порта, просто валидируем
		if ip := net.ParseIP(rawIP); ip != nil {
			return ip.String(), nil
		}
		return "", ErrInvalidIP
	}

	if net.ParseIP(host) == nil {
		return "", ErrInvalidIP
	}

	return net.JoinHostPort(host, port), nil
}
