/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package ecdh

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"strings"
	"testing"

	"github.com/golang/protobuf/proto"
	"github.com/google/tink/go/aead"
	gcmpb "github.com/google/tink/go/proto/aes_gcm_go_proto"
	commonpb "github.com/google/tink/go/proto/common_go_proto"
	tinkpb "github.com/google/tink/go/proto/tink_go_proto"
	"github.com/stretchr/testify/require"

	"github.com/hyperledger/aries-framework-go/pkg/crypto/tinkcrypto/primitive/composite"
	ecdhpb "github.com/hyperledger/aries-framework-go/pkg/crypto/tinkcrypto/primitive/proto/ecdh_aead_go_proto"
	"github.com/hyperledger/aries-framework-go/pkg/internal/cryptoutil"
)

func TestECDHX25519AESPrivateKeyManager_Primitive(t *testing.T) {
	km := newECDHX25519AESPrivateKeyManager()

	t.Run("Test private key manager Primitive() with empty serialized key", func(t *testing.T) {
		p, err := km.Primitive([]byte(""))
		require.EqualError(t, err, errInvalidECDHX25519AESPrivateKey.Error(),
			"ecdhX25519AESPrivateKeyManager primitive from empty serialized key must fail")
		require.Empty(t, p)
	})

	t.Run("Test private key manager Primitive() with bad serialize key", func(t *testing.T) {
		p, err := km.Primitive([]byte("bad.data"))
		require.EqualError(t, err, errInvalidECDHX25519AESPrivateKey.Error(),
			"ecdhX25519AESPrivateKeyManager primitive from bad serialized key must fail")
		require.Empty(t, p)
	})

	format := &gcmpb.AesGcmKeyFormat{
		KeySize: 32,
	}
	serializedFormat, err := proto.Marshal(format)
	require.NoError(t, err)

	format = &gcmpb.AesGcmKeyFormat{
		KeySize: 99, // bad AES128GCM size
	}

	badSerializedFormat, err := proto.Marshal(format)
	require.NoError(t, err)

	flagTests := []struct {
		tcName    string
		version   uint32
		curveType commonpb.EllipticCurveType
		keyType   ecdhpb.KeyType
		encTmp    *tinkpb.KeyTemplate
	}{
		{
			tcName:    "private key manager Primitive() using key with bad version",
			version:   9999,
			curveType: commonpb.EllipticCurveType_CURVE25519,
			keyType:   ecdhpb.KeyType_OKP,
			encTmp:    aead.AES256GCMKeyTemplate(),
		},
		{
			tcName:    "private key manager Primitive() using key with bad curve",
			version:   0,
			curveType: commonpb.EllipticCurveType_UNKNOWN_CURVE,
			keyType:   ecdhpb.KeyType_OKP,
			encTmp:    aead.XChaCha20Poly1305KeyTemplate(),
		},
		{
			tcName:    "private key manager Primitive() using key with bad key type",
			version:   0,
			curveType: commonpb.EllipticCurveType_CURVE25519,
			keyType:   ecdhpb.KeyType_UNKNOWN_KEY_TYPE,
			encTmp:    aead.XChaCha20Poly1305KeyTemplate(),
		},
		{
			tcName:    "success private key manager Primitive()",
			version:   0,
			curveType: commonpb.EllipticCurveType_CURVE25519,
			keyType:   ecdhpb.KeyType_OKP,
			encTmp:    aead.AES256GCMKeyTemplate(),
		},
		{
			tcName:    "private key manager Primitive() using key with bad key template URL",
			version:   0,
			curveType: commonpb.EllipticCurveType_CURVE25519,
			keyType:   ecdhpb.KeyType_OKP,
			encTmp: &tinkpb.KeyTemplate{
				TypeUrl:          "bad.type/url/value",
				Value:            serializedFormat,
				OutputPrefixType: tinkpb.OutputPrefixType_RAW,
			},
		},
		{
			tcName:    "private key manager Primitive() using key with bad dem key size",
			version:   0,
			curveType: commonpb.EllipticCurveType_CURVE25519,
			keyType:   ecdhpb.KeyType_OKP,
			encTmp: &tinkpb.KeyTemplate{
				TypeUrl:          composite.AESGCMTypeURL,
				Value:            badSerializedFormat,
				OutputPrefixType: tinkpb.OutputPrefixType_RAW,
			},
		},
	}

	for _, tc := range flagTests {
		tt := tc
		t.Run("Test "+tt.tcName, func(t *testing.T) {
			pub, pvt, err := ed25519.GenerateKey(rand.Reader)
			require.NoError(t, err)

			x25519Pub, err := cryptoutil.PublicEd25519toCurve25519(pub)
			require.NoError(t, err)

			x25519Pvt, err := cryptoutil.SecretEd25519toCurve25519(pvt)
			require.NoError(t, err)

			params := &ecdhpb.EcdhAeadParams{
				KwParams: &ecdhpb.EcdhKwParams{
					CurveType: tt.curveType, // unknown curve to force an error when calling km.NewKey()
					KeyType:   tt.keyType,   // invalid key type to force error when calling km.Primitive()
				},
				EncParams: &ecdhpb.EcdhAeadEncParams{
					AeadEnc: tt.encTmp,
					CEK:     []byte{},
				},
				EcPointFormat: commonpb.EcPointFormat_UNCOMPRESSED,
			}

			privKeyProto := &ecdhpb.EcdhAeadPrivateKey{
				Version:  tt.version,
				KeyValue: x25519Pvt,
				PublicKey: &ecdhpb.EcdhAeadPublicKey{
					Version: ecdhX25519AESPrivateKeyVersion,
					Params:  params,
					X:       x25519Pub,
				},
			}

			sPrivKey, err := proto.Marshal(privKeyProto)
			require.NoError(t, err)

			p, err := km.Primitive(sPrivKey)
			if bytes.Equal(tt.encTmp.Value, badSerializedFormat) {
				require.EqualError(t, err, errInvalidECDHX25519AESPrivateKey.Error(),
					"ecdhX25519AESPrivateKeyManager primitive from serialized key with invalid serialized key")
				require.Empty(t, p)

				return
			}

			if strings.Contains(tt.tcName, "success") {
				require.NoError(t, err)
				require.NotEmpty(t, p)
				return
			}

			require.Errorf(t, err, tt.tcName)
			require.Empty(t, p)
		})
	}
}

func TestECDHX25519AESPrivateKeyManager_DoesSupport(t *testing.T) {
	km := newECDHX25519AESPrivateKeyManager()
	require.False(t, km.DoesSupport("bad/url"))
	require.True(t, km.DoesSupport(ecdhX25519AESPrivateKeyTypeURL))
}

func TestECDHX25519AESPrivateKeyManager_NewKey(t *testing.T) {
	km := newECDHX25519AESPrivateKeyManager()

	t.Run("Test private key manager NewKey() with nil key", func(t *testing.T) {
		k, err := km.NewKey(nil)
		require.EqualError(t, err, errInvalidECDHX25519AESPrivateKeyFormat.Error())
		require.Empty(t, k)
	})

	t.Run("Test private key manager NewKey() with bad serialize key", func(t *testing.T) {
		p, err := km.NewKey([]byte("bad.data"))
		require.EqualError(t, err, errInvalidECDHX25519AESPrivateKeyFormat.Error(),
			"ecdhX25519AESPrivateKeyManager NewKey() from bad serialized key must fail")
		require.Empty(t, p)
	})

	format := &gcmpb.AesGcmKeyFormat{
		KeySize: 32,
	}

	serializedFormat, err := proto.Marshal(format)
	require.NoError(t, err)

	format = &gcmpb.AesGcmKeyFormat{
		KeySize: 99, // bad AES128GCM size
	}

	badSerializedFormat, err := proto.Marshal(format)
	require.NoError(t, err)

	flagTests := []struct {
		tcName    string
		curveType commonpb.EllipticCurveType
		keyType   ecdhpb.KeyType
		encTmp    *tinkpb.KeyTemplate
	}{
		{
			tcName:    "success private key manager NewKey() and NewKeyData()",
			curveType: commonpb.EllipticCurveType_CURVE25519,
			keyType:   ecdhpb.KeyType_OKP,
			encTmp:    aead.AES256GCMKeyTemplate(),
		},
		{
			tcName:    "private key manager NewKey() and NewKeyData() using key with bad curve",
			curveType: commonpb.EllipticCurveType_UNKNOWN_CURVE,
			keyType:   ecdhpb.KeyType_OKP,
			encTmp:    aead.XChaCha20Poly1305KeyTemplate(),
		},
		{
			tcName:    "private key manager NewKey() and NewKeyData() using key with bad key type",
			curveType: commonpb.EllipticCurveType_CURVE25519,
			keyType:   ecdhpb.KeyType_UNKNOWN_KEY_TYPE,
			encTmp:    aead.AES256GCMKeyTemplate(),
		},
		{
			tcName:    "private key manager NewKey() and NewKeyData() using key with bad key template URL",
			curveType: commonpb.EllipticCurveType_CURVE25519,
			keyType:   ecdhpb.KeyType_OKP,
			encTmp: &tinkpb.KeyTemplate{
				TypeUrl:          "bad.type/url/value",
				Value:            serializedFormat,
				OutputPrefixType: tinkpb.OutputPrefixType_RAW,
			},
		},
		{
			tcName: "private key manager NewKey() and NewKeyData() using key with bad dem key size",
			encTmp: &tinkpb.KeyTemplate{
				TypeUrl:          composite.AESGCMTypeURL,
				Value:            badSerializedFormat,
				OutputPrefixType: tinkpb.OutputPrefixType_RAW,
			},
		},
	}

	for _, tc := range flagTests {
		tt := tc
		t.Run("Test "+tt.tcName, func(t *testing.T) {
			privKeyProto := &ecdhpb.EcdhAeadKeyFormat{
				Params: &ecdhpb.EcdhAeadParams{
					KwParams: &ecdhpb.EcdhKwParams{
						CurveType: tt.curveType, // unknown curve to force an error when calling km.NewKey()
						KeyType:   tt.keyType,   // unknown curve type to force an error when calling km.NewKey()
					},
					EncParams: &ecdhpb.EcdhAeadEncParams{
						AeadEnc: tt.encTmp, // invalid data enc key template to force an error when calling km.NewKey()
					},
					EcPointFormat: commonpb.EcPointFormat_UNCOMPRESSED,
				},
			}

			sPrivKey, err := proto.Marshal(privKeyProto)
			require.NoError(t, err)

			p, err := km.NewKey(sPrivKey)
			if strings.Contains(tt.tcName, "success") {
				require.NoError(t, err)
				require.NotEmpty(t, p)

				sp, e := proto.Marshal(p)
				require.NoError(t, e)
				require.NotEmpty(t, sp)

				// try PublicKeyData() with bad serialized private key
				pubK, e := km.PublicKeyData([]byte("bad serialized private key"))
				require.Error(t, e)
				require.Empty(t, pubK)

				// try PublicKeyData() with valid serialized private key
				pubK, e = km.PublicKeyData(sp)
				require.NoError(t, e)
				require.NotEmpty(t, pubK)
			}

			kd, err := km.NewKeyData(sPrivKey)
			if strings.Contains(tt.tcName, "success") {
				require.NoError(t, err)
				require.NotEmpty(t, kd)
				require.Equal(t, kd.TypeUrl, ecdhX25519AESPrivateKeyTypeURL)
				require.Equal(t, kd.KeyMaterialType, tinkpb.KeyData_ASYMMETRIC_PRIVATE)
				return
			}

			if bytes.Equal(tt.encTmp.Value, badSerializedFormat) {
				require.EqualError(t, err, errInvalidECDHX25519AESPrivateKeyFormat.Error(),
					"ecdhX25519AESPrivateKeyManager NewKey from serialized key with invalid serialized key")
				require.Empty(t, p)

				return
			}

			require.Errorf(t, err, tt.tcName)
			require.Empty(t, p)
		})
	}
}
