package go_vault_jwt

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/alecthomas/assert/v2"
	jwt "github.com/golang-jwt/jwt/v5"
	"github.com/hashicorp/vault/api"
)

type mockLogical struct {
	secret *api.Secret
}

func (m *mockLogical) WriteWithContext(ctx context.Context, path string, data map[string]interface{}) (*api.Secret, error) {
	if m.secret != nil {
		return m.secret, nil
	}
	return nil, errors.New("not implemented")
}

func TestVaultSign(t *testing.T) {
	mockLogical := &mockLogical{&api.Secret{
		Data: map[string]interface{}{
			"signature": "vault:v1:TG1jUE5NSlNYMHBkX0s0Z0d1MTFDVGlCUGg1cGU1MzRTREFpbHlsX09fR08xcGpBY1NybG1pblRPT0lJeE41Mk5hV2xpVEZiXzgtR29vSE5DQXJjaVhnV0NRSTRQMnF6THZnNzNKZ0FSNFdtc2hXWHZVbVJiSlBTS2pSOE05SFI5X1VXTXF2Q19ORlVvSUxKSWN0RThGeVdLOUVLQjFvd2lmMVVrUHNXN25CNFVzenJCbWRFMUxad2N5VVMxaF9nd3d5UGVlZXVOMVZGRTZacGItOTlBaG14ZUVHNmNNUHplek1KaENRR2RDbmJkcXphTHc4c1lKdXJIOW5MTWx6NVpZZFgtMWExU2Z3azBtQkRMOHVINjkxUU5DOUM4NDloM2RUdHZkaGl6MWM4WkRwZkQ4Rml1YWJXWFNzMTFHWXFvQTc1TmQySjUwbEN4TWR5OGVfNWxn",
		},
	}}

	jwtToken := jwt.NewWithClaims(SigningMethodVRS256, jwt.MapClaims{
		"foo": "bar",
		"nbf": time.Date(2015, 10, 10, 12, 0, 0, 0, time.UTC).Unix(),
	})

	key := NewVaultContext(context.Background(), &VaultConfig{
		KeyPath:    "/transit",
		KeyName:    "test-key",
		KeyVersion: 2,
		Logical:    mockLogical,
	})

	payload, err := jwtToken.SignedString(key)
	assert.NoError(t, err)
	assert.Equal(t, payload, "eyJhbGciOiJWUlMyNTYiLCJ0eXAiOiJKV1QifQ.eyJmb28iOiJiYXIiLCJuYmYiOjE0NDQ0Nzg0MDB9.TG1jUE5NSlNYMHBkX0s0Z0d1MTFDVGlCUGg1cGU1MzRTREFpbHlsX09fR08xcGpBY1NybG1pblRPT0lJeE41Mk5hV2xpVEZiXzgtR29vSE5DQXJjaVhnV0NRSTRQMnF6THZnNzNKZ0FSNFdtc2hXWHZVbVJiSlBTS2pSOE05SFI5X1VXTXF2Q19ORlVvSUxKSWN0RThGeVdLOUVLQjFvd2lmMVVrUHNXN25CNFVzenJCbWRFMUxad2N5VVMxaF9nd3d5UGVlZXVOMVZGRTZacGItOTlBaG14ZUVHNmNNUHplek1KaENRR2RDbmJkcXphTHc4c1lKdXJIOW5MTWx6NVpZZFgtMWExU2Z3azBtQkRMOHVINjkxUU5DOUM4NDloM2RUdHZkaGl6MWM4WkRwZkQ4Rml1YWJXWFNzMTFHWXFvQTc1TmQySjUwbEN4TWR5OGVfNWxn")
}

func TestVaultBadSignature(t *testing.T) {
	mockLogical := &mockLogical{&api.Secret{
		Data: map[string]interface{}{
			"signature": "vault:TG1jUE5NSlNYMHBkX0s0Z0d1MTFDVGlCUGg1cGU1MzRTREFpbHlsX09fR08xcGpBY1NybG1pblRPT0lJeE41Mk5hV2xpVEZiXzgtR29vSE5DQXJjaVhnV0NRSTRQMnF6THZnNzNKZ0FSNFdtc2hXWHZVbVJiSlBTS2pSOE05SFI5X1VXTXF2Q19ORlVvSUxKSWN0RThGeVdLOUVLQjFvd2lmMVVrUHNXN25CNFVzenJCbWRFMUxad2N5VVMxaF9nd3d5UGVlZXVOMVZGRTZacGItOTlBaG14ZUVHNmNNUHplek1KaENRR2RDbmJkcXphTHc4c1lKdXJIOW5MTWx6NVpZZFgtMWExU2Z3azBtQkRMOHVINjkxUU5DOUM4NDloM2RUdHZkaGl6MWM4WkRwZkQ4Rml1YWJXWFNzMTFHWXFvQTc1TmQySjUwbEN4TWR5OGVfNWxn",
		},
	}}

	jwtToken := jwt.NewWithClaims(SigningMethodVRS256, jwt.MapClaims{
		"foo": "bar",
		"nbf": time.Date(2015, 10, 10, 12, 0, 0, 0, time.UTC).Unix(),
	})

	key := NewVaultContext(context.Background(), &VaultConfig{
		KeyPath:    "/transit",
		KeyName:    "test-key",
		KeyVersion: 2,
		Logical:    mockLogical,
	})

	_, err := jwtToken.SignedString(key)
	assert.Error(t, err)
}
