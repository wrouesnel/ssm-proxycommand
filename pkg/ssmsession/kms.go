package ssmsession

import (
	"context"
	"errors"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/kms"

	"github.com/wrouesnel/ssm-proxycommand/pkg/ssmproto"
)

// KMSClient is the subset of the KMS API needed for encrypted sessions.
type KMSClient interface {
	GenerateDataKey(ctx context.Context, in *kms.GenerateDataKeyInput, optFns ...func(*kms.Options)) (*kms.GenerateDataKeyOutput, error)
}

// newKMSEncrypter generates the session data key the way session-manager-plugin does.
func newKMSEncrypter(ctx context.Context, client KMSClient, keyID, sessionID, targetID string) (*ssmproto.Encrypter, error) {
	if client == nil {
		return nil, errors.New("session requires KMS encryption but no KMS client is configured")
	}
	out, err := client.GenerateDataKey(ctx, &kms.GenerateDataKeyInput{
		KeyId:         aws.String(keyID),
		NumberOfBytes: aws.Int32(64),
		EncryptionContext: map[string]string{
			"aws:ssm:SessionId": sessionID,
			"aws:ssm:TargetId":  targetID,
		},
	})
	if err != nil {
		return nil, fmt.Errorf("generating KMS data key: %w", err)
	}
	return ssmproto.NewEncrypter(out.Plaintext, out.CiphertextBlob)
}
