package releaseinfo

import (
	"context"
	"sync"
	"testing"

	. "github.com/onsi/gomega"

	"github.com/docker/distribution"
	imagev1 "github.com/openshift/api/image/v1"
	"github.com/openshift/hypershift/support/thirdparty/library-go/pkg/image/reference"
)

func TestProviderWithOpenShiftImageRegistryOverridesDecorator_Lookup(t *testing.T) {
	g := NewWithT(t)

	// Create mock resources.
	mirroredReleaseImage := "quay.io/openshift-release-dev/ocp-release:4.16.13-x86_64"
	canonicalReleaseImage := "canonical-release-image"
	releaseImage := &ReleaseImage{
		ImageStream:    &imagev1.ImageStream{},
		StreamMetadata: &CoreOSStreamMetadata{},
	}

	// Create registry providers delegating to a cached provider so we can mock the cache content for the mirroredReleaseImage.
	delegate := &RegistryMirrorProviderDecorator{
		Delegate: &CachedProvider{
			Inner: &RegistryClientProvider{},
			Cache: map[string]*ReleaseImage{
				mirroredReleaseImage: releaseImage,
			},
		},
		RegistryOverrides: map[string]string{},
	}
	provider := &ProviderWithOpenShiftImageRegistryOverridesDecorator{
		Delegate: delegate,
		OpenShiftImageRegistryOverrides: map[string][]string{
			canonicalReleaseImage: {mirroredReleaseImage},
		},
		// Mock repoSetupFn to avoid real network calls for mirror verification.
		repoSetupFn: func(ctx context.Context, imageRef string, pullSecret []byte) (distribution.Repository, *reference.DockerImageReference, error) {
			ref, _ := reference.Parse(imageRef)
			return nil, &ref, nil
		},
		lock: sync.Mutex{},
	}

	pullSecret := []byte(`{"auths":{}}`)
	// Call the Lookup method and validate GetMirroredReleaseImage.
	_, err := provider.Lookup(t.Context(), canonicalReleaseImage, pullSecret)
	g.Expect(err).ToNot(HaveOccurred())
	g.Expect(provider.GetMirroredReleaseImage()).To(Equal(mirroredReleaseImage))
}
