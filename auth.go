package xauth

import (
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

type Config struct {
	SigningKey              string // Secret key
	AccessTokenExpiryHours  int    // อายุ Access Token
	RefreshTokenExpiryHours int    // อายุ Refresh Token
}

type Claims struct {
	UserID int64  `json:"uid"`
	Role   string `json:"role"`

	jwt.RegisteredClaims
}

// Service คือ Interface ที่ Service อื่นๆ จะเรียกใช้

type Service interface {
	// สร้าง Token คู่ (Access + Refresh)
	CreateTokens(userID int64, role string) (accessToken string, refreshToken string, err error)
	// ตรวจสอบ Access Token และคืนค่า Claims ออกมา
	VerifyAccessToken(tokenString string) (*Claims, error)
}

type jwtService struct {
	cfg Config

	jwtKey []byte
}

func NewService(cfg Config) (Service, error) {
	if cfg.SigningKey == "" {
		return nil, fmt.Errorf("auth config: SigningKey is required")
	}
	if cfg.AccessTokenExpiryHours == 0 {
		cfg.AccessTokenExpiryHours = 1
	}
	if cfg.RefreshTokenExpiryHours == 0 {
		cfg.RefreshTokenExpiryHours = 72
	}

	return &jwtService{
		cfg:    cfg,
		jwtKey: []byte(cfg.SigningKey),
	}, nil
}

func (s *jwtService) CreateTokens(userID int64, role string) (string, string, error) {
	// 1. สร้าง Access Token
	accessExpiry := time.Now().Add(time.Hour * time.Duration(s.cfg.AccessTokenExpiryHours))
	accessClaims := &Claims{
		UserID: userID,
		Role:   role,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(accessExpiry),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
		},
	}
	accessToken := jwt.NewWithClaims(jwt.SigningMethodHS256, accessClaims)
	accTokenString, err := accessToken.SignedString(s.jwtKey)
	if err != nil {
		return "", "", fmt.Errorf("failed to sign access token: %w", err)
	}

	// 2. สร้าง Refresh Token
	refreshExpiry := time.Now().Add(time.Hour * time.Duration(s.cfg.RefreshTokenExpiryHours))
	refreshClaims := &Claims{
		UserID: userID,
		Role:   role, // อาจจะไม่ต้องใส่ Role ใน Refresh ก็ได้
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(refreshExpiry),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
		},
	}
	refreshToken := jwt.NewWithClaims(jwt.SigningMethodHS256, refreshClaims)
	refTokenString, err := refreshToken.SignedString(s.jwtKey)
	if err != nil {
		return "", "", fmt.Errorf("failed to sign refresh token: %w", err)
	}

	return accTokenString, refTokenString, nil
}

// VerifyAccessToken (Implementation)
func (s *jwtService) VerifyAccessToken(tokenString string) (*Claims, error) {
	// Parse token
	token, err := jwt.ParseWithClaims(tokenString, &Claims{}, func(token *jwt.Token) (interface{}, error) {

		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return s.jwtKey, nil
	})

	if err != nil {
		return nil, fmt.Errorf("failed to parse token: %w", err)
	}

	if claims, ok := token.Claims.(*Claims); ok && token.Valid {
		return claims, nil
	}

	return nil, fmt.Errorf("invalid token")
}
