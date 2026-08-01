/*
Copyright © The ESO Authors

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    https://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package terraform

import (
	"context"
	"errors"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	s3types "github.com/aws/aws-sdk-go-v2/service/s3/types"

	esv1 "github.com/external-secrets/external-secrets/apis/externalsecrets/v1"
	awsauth "github.com/external-secrets/external-secrets/providers/v1/aws/auth"
	"github.com/external-secrets/external-secrets/runtime/esutils"
	"github.com/external-secrets/external-secrets/runtime/metrics"
)

// s3API is the slice of the S3 client the backend uses, so tests can stub it.
type s3API interface {
	GetObject(ctx context.Context, params *s3.GetObjectInput, optFns ...func(*s3.Options)) (*s3.GetObjectOutput, error)
}

func newS3Fetcher(ctx context.Context, backend *esv1.TerraformS3Backend, opts backendOpts) (fetcher, error) {
	cfg, err := awsauth.NewSessionFromAuth(ctx, awsauth.SessionOpts{
		Auth:        backend.Auth,
		Role:        backend.Role,
		Region:      backend.Region,
		StoreKind:   opts.storeKind,
		Kube:        opts.kube,
		Namespace:   opts.namespace,
		AssumeRoler: awsauth.DefaultSTSProvider,
		JWTProvider: awsauth.DefaultJWTProvider,
	})
	if err != nil {
		return nil, fmt.Errorf("cannot construct AWS session: %w", err)
	}

	api := s3.NewFromConfig(*cfg, func(o *s3.Options) {
		if backend.Endpoint != "" {
			o.BaseEndpoint = aws.String(backend.Endpoint)
		}
		o.UsePathStyle = backend.ForcePathStyle
	})

	return s3Fetcher(api, backend.Bucket, backend.Key), nil
}

func s3Fetcher(api s3API, bucket, key string) fetcher {
	return func(ctx context.Context) ([]byte, error) {
		out, err := api.GetObject(ctx, &s3.GetObjectInput{
			Bucket: aws.String(bucket),
			Key:    aws.String(key),
		})
		metrics.ObserveAPICall(metricsProvider, metricsCallS3GetObject, err)
		if err != nil {
			var noSuchKey *s3types.NoSuchKey
			var notFound *s3types.NotFound
			if errors.As(err, &noSuchKey) || errors.As(err, &notFound) {
				return nil, fmt.Errorf("state object %q not found in bucket %q", key, bucket)
			}
			return nil, fmt.Errorf("cannot read state object %q from bucket %q: %w", key, bucket, err)
		}
		defer func() { _ = out.Body.Close() }()

		return readCapped(out.Body)
	}
}

func validateS3Backend(store esv1.GenericStore, backend *esv1.TerraformS3Backend) error {
	if backend.Bucket == "" {
		return errors.New("s3 backend requires a bucket")
	}
	if backend.Key == "" {
		return errors.New("s3 backend requires a key")
	}
	if backend.Region == "" {
		return errors.New("s3 backend requires a region")
	}
	if ref := backend.Auth.SecretRef; ref != nil {
		if err := esutils.ValidateReferentSecretSelector(store, ref.AccessKeyID); err != nil {
			return fmt.Errorf("invalid accessKeyIDSecretRef: %w", err)
		}
		if err := esutils.ValidateReferentSecretSelector(store, ref.SecretAccessKey); err != nil {
			return fmt.Errorf("invalid secretAccessKeySecretRef: %w", err)
		}
		if ref.SessionToken != nil {
			if err := esutils.ValidateReferentSecretSelector(store, *ref.SessionToken); err != nil {
				return fmt.Errorf("invalid sessionTokenSecretRef: %w", err)
			}
		}
	}
	if jwt := backend.Auth.JWTAuth; jwt != nil {
		if jwt.ServiceAccountRef == nil {
			return errors.New("jwt auth requires a serviceAccountRef")
		}
		if err := esutils.ValidateReferentServiceAccountSelector(store, *jwt.ServiceAccountRef); err != nil {
			return fmt.Errorf("invalid serviceAccountRef: %w", err)
		}
	}
	return nil
}
