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
			"signature": "vault:v1:LmcPNMJSX0pd_K4gGu11CTiBPh5pe534SDAilyl_O_GO1pjAcSrlminTOOIIxN52NaWliTFb_8-GooHNCArciXgWCQI4P2qzLvg73JgAR4WmshWXvUmRbJPSKjR8M9HR9_UWMqvC_NFUoILJIctE8FyWK9EKB1owif1UkPsW7nB4UszrBmdE1LZwcyUS1h_gwwyPeeeuN1VFE6Zpb-99AhmxeEG6cMPzezMJhCQGdCnbdqzaLw8sYJurH9nLMlz5ZYdX-1a1Sfwk0mBDL8uH691QNC9C849h3dTtvdhiz1c8ZDpfD8FiuabWXSs11GYqoA75Nd2J50lCxMdy8e_5lg",
		},
	}}

	jwtToken := jwt.NewWithClaims(SigningMethodRS256, jwt.MapClaims{
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
	assert.Equal(t, payload, "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJmb28iOiJiYXIiLCJuYmYiOjE0NDQ0Nzg0MDB9.LmcPNMJSX0pd_K4gGu11CTiBPh5pe534SDAilyl_O_GO1pjAcSrlminTOOIIxN52NaWliTFb_8-GooHNCArciXgWCQI4P2qzLvg73JgAR4WmshWXvUmRbJPSKjR8M9HR9_UWMqvC_NFUoILJIctE8FyWK9EKB1owif1UkPsW7nB4UszrBmdE1LZwcyUS1h_gwwyPeeeuN1VFE6Zpb-99AhmxeEG6cMPzezMJhCQGdCnbdqzaLw8sYJurH9nLMlz5ZYdX-1a1Sfwk0mBDL8uH691QNC9C849h3dTtvdhiz1c8ZDpfD8FiuabWXSs11GYqoA75Nd2J50lCxMdy8e_5lg")
}

func TestVaultBadSignature(t *testing.T) {
	mockLogical := &mockLogical{&api.Secret{
		Data: map[string]interface{}{
			"signature": "vault:LmcPNMJSX0pd_K4gGu11CTiBPh5pe534SDAilyl_O_GO1pjAcSrlminTOOIIxN52NaWliTFb_8-GooHNCArciXgWCQI4P2qzLvg73JgAR4WmshWXvUmRbJPSKjR8M9HR9_UWMqvC_NFUoILJIctE8FyWK9EKB1owif1UkPsW7nB4UszrBmdE1LZwcyUS1h_gwwyPeeeuN1VFE6Zpb-99AhmxeEG6cMPzezMJhCQGdCnbdqzaLw8sYJurH9nLMlz5ZYdX-1a1Sfwk0mBDL8uH691QNC9C849h3dTtvdhiz1c8ZDpfD8FiuabWXSs11GYqoA75Nd2J50lCxMdy8e_5lg",
		},
	}}

	jwtToken := jwt.NewWithClaims(SigningMethodRS256, jwt.MapClaims{
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
