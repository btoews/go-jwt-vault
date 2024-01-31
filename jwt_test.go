package go_vault_jwt

import (
	"context"
	"testing"
	"time"

	"github.com/alecthomas/assert/v2"
	jwt "github.com/golang-jwt/jwt/v5"
	"github.com/hashicorp/vault/api"
)

// type mockVaultClient struct {
// }

// func (m mockVaultClient) Logical() mockLogical {
// 	return &mockLogical{}
// }

type mockLogical struct {
}

func (m *mockLogical) WriteWithContext(ctx context.Context, path string, data map[string]interface{}) (*api.Secret, error) {
	// args := m.Called(ctx, path, data)
	// return args.Get(0).(*api.Secret), args.Error(1)
	return &api.Secret{
		Data: map[string]interface{}{
			"signature": "vault:v1:TG1jUE5NSlNYMHBkX0s0Z0d1MTFDVGlCUGg1cGU1MzRTREFpbHlsX09fR08xcGpBY1NybG1pblRPT0lJeE41Mk5hV2xpVEZiXzgtR29vSE5DQXJjaVhnV0NRSTRQMnF6THZnNzNKZ0FSNFdtc2hXWHZVbVJiSlBTS2pSOE05SFI5X1VXTXF2Q19ORlVvSUxKSWN0RThGeVdLOUVLQjFvd2lmMVVrUHNXN25CNFVzenJCbWRFMUxad2N5VVMxaF9nd3d5UGVlZXVOMVZGRTZacGItOTlBaG14ZUVHNmNNUHplek1KaENRR2RDbmJkcXphTHc4c1lKdXJIOW5MTWx6NVpZZFgtMWExU2Z3azBtQkRMOHVINjkxUU5DOUM4NDloM2RUdHZkaGl6MWM4WkRwZkQ4Rml1YWJXWFNzMTFHWXFvQTc1TmQySjUwbEN4TWR5OGVfNWxn",
		},
	}, nil
}

func TestVaultSign(t *testing.T) {
	mockLogical := &mockLogical{}

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
