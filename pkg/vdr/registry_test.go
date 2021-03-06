/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package vdr

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/hyperledger/aries-framework-go/pkg/doc/did"
	vdrapi "github.com/hyperledger/aries-framework-go/pkg/framework/aries/api/vdr"
	"github.com/hyperledger/aries-framework-go/pkg/framework/aries/api/vdr/create"
	"github.com/hyperledger/aries-framework-go/pkg/framework/aries/api/vdr/doc"
	"github.com/hyperledger/aries-framework-go/pkg/framework/aries/api/vdr/resolve"
	"github.com/hyperledger/aries-framework-go/pkg/kms"
	mockkms "github.com/hyperledger/aries-framework-go/pkg/mock/kms"
	mockprovider "github.com/hyperledger/aries-framework-go/pkg/mock/provider"
	mockvdr "github.com/hyperledger/aries-framework-go/pkg/mock/vdr"
)

func TestRegistry_New(t *testing.T) {
	t.Run("test new success", func(t *testing.T) {
		registry := New(&mockprovider.Provider{})
		require.NotNil(t, registry)
	})
	t.Run("test new with opts success", func(t *testing.T) {
		const sampleSvcType = "sample-svc-type"
		const sampleSvcEndpoint = "sample-svc-endpoint"
		registry := New(&mockprovider.Provider{},
			WithDefaultServiceEndpoint(sampleSvcEndpoint), WithDefaultServiceType(sampleSvcType))
		require.NotNil(t, registry)
		require.Equal(t, sampleSvcEndpoint, registry.defServiceEndpoint)
		require.Equal(t, sampleSvcType, registry.defServiceType)
	})
}

func TestRegistry_Close(t *testing.T) {
	t.Run("test success", func(t *testing.T) {
		registry := New(&mockprovider.Provider{})
		require.NoError(t, registry.Close())
	})
	t.Run("test error", func(t *testing.T) {
		registry := New(&mockprovider.Provider{},
			WithVDR(&mockvdr.MockVDR{CloseErr: fmt.Errorf("close error")}))
		err := registry.Close()
		require.Error(t, err)
		require.Contains(t, err.Error(), "close error")
	})
}

func TestRegistry_Resolve(t *testing.T) {
	t.Run("test invalid did input", func(t *testing.T) {
		registry := New(&mockprovider.Provider{})
		d, err := registry.Resolve("id")
		require.Error(t, err)
		require.Contains(t, err.Error(), "wrong format did input")
		require.Nil(t, d)
	})

	t.Run("test did method not supported", func(t *testing.T) {
		registry := New(&mockprovider.Provider{}, WithVDR(&mockvdr.MockVDR{AcceptValue: false}))
		d, err := registry.Resolve("1:id:123")
		require.Error(t, err)
		require.Contains(t, err.Error(), "did method id not supported for vdr")
		require.Nil(t, d)
	})

	t.Run("test DID not found", func(t *testing.T) {
		registry := New(&mockprovider.Provider{}, WithVDR(&mockvdr.MockVDR{
			AcceptValue: true, ReadFunc: func(didID string, opts ...resolve.Option) (*did.Doc, error) {
				return nil, vdrapi.ErrNotFound
			},
		}))
		d, err := registry.Resolve("1:id:123")
		require.Error(t, err)
		require.Contains(t, err.Error(), vdrapi.ErrNotFound.Error())
		require.Nil(t, d)
	})

	t.Run("test error from resolve did", func(t *testing.T) {
		registry := New(&mockprovider.Provider{}, WithVDR(&mockvdr.MockVDR{
			AcceptValue: true, ReadFunc: func(didID string, opts ...resolve.Option) (*did.Doc, error) {
				return nil, fmt.Errorf("read error")
			},
		}))
		d, err := registry.Resolve("1:id:123")
		require.Error(t, err)
		require.Contains(t, err.Error(), "read error")
		require.Nil(t, d)
	})

	t.Run("test opts passed", func(t *testing.T) {
		registry := New(&mockprovider.Provider{}, WithVDR(&mockvdr.MockVDR{
			AcceptValue: true, ReadFunc: func(didID string, opts ...resolve.Option) (*did.Doc, error) {
				resolveOpts := &resolve.Opts{}
				// Apply options
				for _, opt := range opts {
					opt(resolveOpts)
				}
				require.Equal(t, "1", resolveOpts.VersionID)
				return nil, nil
			},
		}))
		_, err := registry.Resolve("1:id:123", resolve.WithVersionID("1"))
		require.NoError(t, err)
	})

	t.Run("test success", func(t *testing.T) {
		registry := New(&mockprovider.Provider{}, WithVDR(&mockvdr.MockVDR{AcceptValue: true}))
		_, err := registry.Resolve("1:id:123")
		require.NoError(t, err)
	})
}

func TestRegistry_Store(t *testing.T) {
	t.Run("test invalid did input", func(t *testing.T) {
		registry := New(&mockprovider.Provider{})
		err := registry.Store(&did.Doc{ID: "id"})
		require.Error(t, err)
		require.Contains(t, err.Error(), "wrong format did input")
	})

	t.Run("test did method not supported", func(t *testing.T) {
		registry := New(&mockprovider.Provider{}, WithVDR(&mockvdr.MockVDR{AcceptValue: false}))
		err := registry.Store(&did.Doc{ID: "1:id:123"})
		require.Error(t, err)
		require.Contains(t, err.Error(), "did method id not supported for vdr")
	})

	t.Run("test success", func(t *testing.T) {
		registry := New(&mockprovider.Provider{}, WithVDR(&mockvdr.MockVDR{AcceptValue: true}))
		err := registry.Store(&did.Doc{ID: "1:id:123"})
		require.NoError(t, err)
	})
}

func TestRegistry_Create(t *testing.T) {
	t.Run("test did method not supported", func(t *testing.T) {
		registry := New(&mockprovider.Provider{KMSValue: &mockkms.KeyManager{}},
			WithVDR(&mockvdr.MockVDR{AcceptValue: false}))
		d, err := registry.Create("id")
		require.Error(t, err)
		require.Contains(t, err.Error(), "did method id not supported for vdr")
		require.Nil(t, d)
	})
	t.Run("test opts is passed", func(t *testing.T) {
		kh, err := mockkms.CreateMockAESGCMKeyHandle()
		require.NoError(t, err)

		registry := New(&mockprovider.Provider{KMSValue: &mockkms.KeyManager{
			CreateKeyID:    "123",
			CreateKeyValue: kh,
		}},
			WithVDR(&mockvdr.MockVDR{
				AcceptValue: true,
				BuildFunc: func(keyManager kms.KeyManager, opts ...create.Option) (doc *did.Doc, e error) {
					docOpts := &create.Opts{}
					// Apply options
					for _, opt := range opts {
						opt(docOpts)
					}
					require.Equal(t, "key1", docOpts.PublicKeys[0].ID)
					return &did.Doc{ID: "1:id:123"}, nil
				},
			}))
		_, err = registry.Create("id", create.WithPublicKey(&doc.PublicKey{ID: "key1"}))
		require.NoError(t, err)
	})
	t.Run("with KMS opts - test opts is passed ", func(t *testing.T) {
		registry := New(&mockprovider.Provider{KMSValue: &mockkms.KeyManager{}},
			WithVDR(&mockvdr.MockVDR{
				AcceptValue: true,
				BuildFunc: func(keyManager kms.KeyManager, opts ...create.Option) (doc *did.Doc, e error) {
					docOpts := &create.Opts{}
					// Apply options
					for _, opt := range opts {
						opt(docOpts)
					}
					require.Equal(t, "key1", docOpts.PublicKeys[0].ID)
					return &did.Doc{ID: "1:id:123"}, nil
				},
			}))
		_, err := registry.Create("id", create.WithPublicKey(&doc.PublicKey{ID: "key1"}))
		require.NoError(t, err)
	})
	t.Run("test error from build doc", func(t *testing.T) {
		registry := New(&mockprovider.Provider{KMSValue: &mockkms.KeyManager{}},
			WithVDR(&mockvdr.MockVDR{
				AcceptValue: true,
				BuildFunc: func(keyManager kms.KeyManager, opts ...create.Option) (doc *did.Doc, e error) {
					return nil, fmt.Errorf("build did error")
				},
			}))
		d, err := registry.Create("id")
		require.Error(t, err)
		require.Contains(t, err.Error(), "build did error")
		require.Nil(t, d)
	})
	t.Run("test error from store doc", func(t *testing.T) {
		registry := New(&mockprovider.Provider{KMSValue: &mockkms.KeyManager{}},
			WithVDR(&mockvdr.MockVDR{
				AcceptValue: true, StoreErr: fmt.Errorf("store error"),
				BuildFunc: func(keyManager kms.KeyManager, opts ...create.Option) (doc *did.Doc, e error) {
					return &did.Doc{ID: "1:id:123"}, nil
				},
			}))
		d, err := registry.Create("id")
		require.Error(t, err)
		require.Contains(t, err.Error(), "store error")
		require.Nil(t, d)
	})
	t.Run("test success", func(t *testing.T) {
		registry := New(&mockprovider.Provider{KMSValue: &mockkms.KeyManager{}},
			WithVDR(&mockvdr.MockVDR{
				AcceptValue: true,
				BuildFunc: func(keyManager kms.KeyManager, opts ...create.Option) (doc *did.Doc, e error) {
					return &did.Doc{ID: "1:id:123"}, nil
				},
			}))
		_, err := registry.Create("id")
		require.NoError(t, err)
	})
}
