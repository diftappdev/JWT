package xauth

import "context"

// เราใช้ custom type เพื่อป้องกันการชนกันของ key ใน context
type contextKey string

const claimsKey = contextKey("xauth_claims")

// NewContextWithClaims ฝัง Claims ลงไปใน context
func NewContextWithClaims(ctx context.Context, claims *Claims) context.Context {
	return context.WithValue(ctx, claimsKey, claims)
}

// ClaimsFromContext ดึง Claims ออกมาจาก context
// Handler ปลายทางจะเรียกใช้ฟังก์ชันนี้
func ClaimsFromContext(ctx context.Context) (*Claims, bool) {
	claims, ok := ctx.Value(claimsKey).(*Claims)
	return claims, ok
}
