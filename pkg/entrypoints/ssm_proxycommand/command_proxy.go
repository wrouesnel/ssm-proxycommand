package ssm_proxycommand

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os/exec"
	"strconv"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/ssm"
	"github.com/wrouesnel/ctxstdio"
	logutil "github.com/wrouesnel/go.logutil"
	"go.uber.org/zap"

	"github.com/wrouesnel/ssm-proxycommand/pkg/ssmsession"
)

// ProxyCmd is the ProxyCommand entry point.
type ProxyCmd struct {
	Host     string `arg:""                                                                                            help:"Hostname from ssh (%h)."`
	Port     int    `arg:""                                                                                            default:"22"                                      help:"Port on the instance (%p)." optional:""`
	Document string `default:"AWS-StartSSHSession"                                                                     help:"SSM document that starts the port session."`
	Reason   string `help:"Reason recorded against the session in CloudTrail."`
	Plugin   bool   `help:"Use the session-manager-plugin binary for the data channel instead of the built-in client."`
}

func (c *ProxyCmd) Run(ctx context.Context, g *Globals) error {
	log := logutil.FromCtx(ctx)
	t, err := resolveTarget(ctx, g, c.Host)
	if err != nil {
		return err
	}
	ssmClient := ssm.NewFromConfig(t.cfg)
	in := &ssm.StartSessionInput{
		Target:       aws.String(t.match.InstanceID),
		DocumentName: aws.String(c.Document),
		Parameters:   map[string][]string{"portNumber": {strconv.Itoa(c.Port)}},
	}
	if c.Reason != "" {
		in.Reason = aws.String(c.Reason)
	}
	out, err := ssmClient.StartSession(ctx, in)
	if err != nil {
		return withCredentialHint(fmt.Errorf("starting SSM session to %s: %w", t.match.InstanceID, err), t.spec.Profile)
	}
	sessionID := aws.ToString(out.SessionId)
	log.Info("session started", zap.String("session", sessionID))
	defer terminateSession(ssmClient, sessionID, log)

	if c.Plugin {
		return runPlugin(ctx, t, in, out)
	}
	return ssmsession.Run(ctx, ssmsession.Options{
		SessionID:   sessionID,
		StreamURL:   aws.ToString(out.StreamUrl),
		TokenValue:  aws.ToString(out.TokenValue),
		TargetID:    t.match.InstanceID,
		Region:      t.cfg.Region,
		Credentials: t.cfg.Credentials,
		KMS:         kms.NewFromConfig(t.cfg),
		Resume: func(ctx context.Context) (string, string, error) {
			r, err := ssmClient.ResumeSession(ctx, &ssm.ResumeSessionInput{SessionId: out.SessionId})
			if err != nil {
				return "", "", err
			}
			return aws.ToString(r.TokenValue), aws.ToString(r.StreamUrl), nil
		},
		Stderr: ctxstdio.StdErr(ctx),
	}, ctxstdio.Stdin(ctx), ctxstdio.StdOut(ctx))
}

func terminateSession(client *ssm.Client, sessionID string, log *zap.Logger) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err := client.TerminateSession(ctx, &ssm.TerminateSessionInput{SessionId: aws.String(sessionID)}); err != nil {
		log.Debug("terminating session", zap.String("session", sessionID), zap.Error(err))
	}
}

// runPlugin hands the session to session-manager-plugin, the way the AWS CLI does.
func runPlugin(ctx context.Context, t *target, in *ssm.StartSessionInput, out *ssm.StartSessionOutput) error {
	resp, _ := json.Marshal(map[string]string{
		"SessionId":  aws.ToString(out.SessionId),
		"StreamUrl":  aws.ToString(out.StreamUrl),
		"TokenValue": aws.ToString(out.TokenValue),
	})
	req, _ := json.Marshal(map[string]any{
		"Target":       aws.ToString(in.Target),
		"DocumentName": aws.ToString(in.DocumentName),
		"Parameters":   in.Parameters,
	})
	cmd := exec.CommandContext(ctx, "session-manager-plugin", string(resp), t.cfg.Region, "StartSession", t.spec.Profile, string(req), "")
	cmd.Stdin, cmd.Stdout, cmd.Stderr = ctxstdio.Stdin(ctx), ctxstdio.StdOut(ctx), ctxstdio.StdErr(ctx)
	if err := cmd.Run(); err != nil {
		if errors.Is(err, exec.ErrNotFound) {
			return fmt.Errorf("--plugin needs session-manager-plugin on PATH: %w", err)
		}
		return fmt.Errorf("session-manager-plugin: %w", err)
	}
	return nil
}
