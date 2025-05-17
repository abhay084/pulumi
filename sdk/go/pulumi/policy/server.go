// Copyright 2025, Pulumi Corporation.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package policy

import (
	"context"
	"errors"
	"fmt"
	"os"
	"regexp"

	"github.com/pulumi/pulumi/sdk/v3/go/common/resource"
	"github.com/pulumi/pulumi/sdk/v3/go/common/util/contract"
	"github.com/pulumi/pulumi/sdk/v3/go/common/version"

	pbempty "github.com/golang/protobuf/ptypes/empty"
	"github.com/pulumi/pulumi/sdk/v3/go/common/resource/plugin"
	logger "github.com/pulumi/pulumi/sdk/v3/go/common/util/logging"
	"github.com/pulumi/pulumi/sdk/v3/go/common/util/rpcutil"
	pulumirpc "github.com/pulumi/pulumi/sdk/v3/proto/go"
	"google.golang.org/grpc"
)

var policyPackNameRE = regexp.MustCompile(`^[a-zA-Z0-9-_.]{1,100}$`)

func Serve[T ValidationPolicy](name string, policies Policies[T]) error {
	if name == "" || !policyPackNameRE.MatchString(name) {
		logger.V(1).Infof("Invalid policy pack name %q. Policy pack names may only contain alphanumerics, hyphens, "+
			"underscores, or periods.", name)
		return fmt.Errorf("invalid policy pack name: %q", name)
	}

	for _, policy := range policies {
		if policy.Name == "all" {
			return fmt.Errorf("invalid policy name %[1]q. %[1]q is a reserved name", policy.Name)
		}

		if policy.ConfigSchema != nil {
			if _, ok := policy.ConfigSchema.Properties["enforcementLevel"]; ok {
				return errors.New("enforcementLevel cannot be explicitly specified in configSchema properties")
			}
			for _, req := range policy.ConfigSchema.Required {
				if req == "enforcementLevel" {
					return errors.New("enforcementLevel cannot be required in configSchema")
				}
			}
		}
	}

	// Fire up a gRPC server, letting the kernel choose a free port for us.
	port, done, err := rpcutil.Serve(0, nil, []func(*grpc.Server) error{
		func(srv *grpc.Server) error {
			analyzer := &analyzerServer[T]{
				policyPackName: name,
				policies:       policies,
			}
			pulumirpc.RegisterAnalyzerServer(srv, analyzer)
			return nil
		},
	}, nil)
	if err != nil {
		return fmt.Errorf("fatal: %v", err)
	}

	// The analyzer protocol requires that we now write out the port we have chosen to listen on.
	fmt.Printf("%d\n", port)

	// Finally, wait for the server to stop serving.
	if err := <-done; err != nil {
		return fmt.Errorf("fatal: %v", err)
	}

	return nil
}

type analyzerServer[T ValidationPolicy] struct {
	pulumirpc.UnimplementedAnalyzerServer

	policyPackName   string
	policies         Policies[T]
	policyPackConfig map[string]interface{}
}

func (a *analyzerServer[T]) Handshake(
	ctx context.Context,
	req *pulumirpc.AnalyzerHandshakeRequest,
) (*pulumirpc.AnalyzerHandshakeResponse, error) {
	// TODO: We should grab the engine address and setup a logger for it.
	return &pulumirpc.AnalyzerHandshakeResponse{}, nil
}

func (a *analyzerServer[T]) Analyze(ctx context.Context, req *pulumirpc.AnalyzeRequest) (*pulumirpc.AnalyzeResponse, error) {
	switch v := any(a).(type) {
	case *analyzerServer[ResourceValidationPolicy]:
		var ds []*pulumirpc.AnalyzeDiagnostic
		for _, p := range a.policies {
			defaultReportViolation := func(message string, urn string) {
				violationMessage := p.Description
				if message != "" {
					violationMessage += fmt.Sprintf("\n%s", message)
				}

				ds = append(ds, &pulumirpc.AnalyzeDiagnostic{
					PolicyName:       p.Name,
					PolicyPackName:   a.policyPackName,
					Description:      p.Description,
					Message:          violationMessage,
					EnforcementLevel: pulumirpc.EnforcementLevel(p.EnforcementLevel),
					Urn:              urn,
				})
			}
			args := ResourceValidationArgs{
				Resource: &pulumirpc.AnalyzerResource{
					Type:                 req.GetType(),
					Properties:           req.GetProperties(),
					Urn:                  req.GetUrn(),
					Name:                 req.GetName(),
					Options:              req.GetOptions(),
					Provider:             req.GetProvider(),
					Parent:               "",  /* TODO */
					Dependencies:         nil, /* TODO */
					PropertyDependencies: nil, /* TODO */
				},
			}

			switch f := any(p.ValidationPolicy).(type) {
			case func() ResourceValidationPolicy:
				_, _ = fmt.Fprintf(os.Stderr, "Calling resource validation policy: %q on URN: %q\n", p.Name, req.GetUrn())
				f()(args, defaultReportViolation)
			default:
				contract.Failf("unexpected policy type %T", f)
			}
		}
		return &pulumirpc.AnalyzeResponse{
			Diagnostics: ds,
		}, nil
	default:
		return nil, fmt.Errorf("analyze unexpected on stack validation policypack: %q type: %T", a.policyPackName, v)
	}
}

func (a *analyzerServer[T]) AnalyzeStack(ctx context.Context, req *pulumirpc.AnalyzeStackRequest) (*pulumirpc.
	AnalyzeResponse,
	error,
) {
	switch any(a).(type) {
	case *analyzerServer[StackValidationPolicy]:
		var ds []*pulumirpc.AnalyzeDiagnostic
		for _, p := range a.policies {
			defaultReportViolation := func(message string, urn string) {
				violationMessage := p.Description
				if message != "" {
					violationMessage += fmt.Sprintf("\n%s", message)
				}

				ds = append(ds, &pulumirpc.AnalyzeDiagnostic{
					PolicyName:       p.Name,
					PolicyPackName:   a.policyPackName,
					Description:      p.Description,
					Message:          violationMessage,
					EnforcementLevel: pulumirpc.EnforcementLevel(p.EnforcementLevel),
					Urn:              urn,
				})
			}

			var resources []*pulumirpc.AnalyzerResource
			for _, r := range req.GetResources() {
				resources = append(resources, &pulumirpc.AnalyzerResource{
					Type:                 r.GetType(),
					Properties:           r.GetProperties(),
					Urn:                  r.GetUrn(),
					Name:                 r.GetName(),
					Options:              r.GetOptions(),
					Provider:             r.GetProvider(),
					Parent:               r.GetParent(),
					Dependencies:         r.GetDependencies(),
					PropertyDependencies: r.GetPropertyDependencies(),
				})
			}
			args := StackValidationArgs{
				Resources: resources,
			}
			switch f := any(p.ValidationPolicy).(type) {
			case func() StackValidationPolicy:
				f()(args, defaultReportViolation)
			default:
				contract.Fail()
			}
		}
		return &pulumirpc.AnalyzeResponse{
			Diagnostics: ds,
		}, nil
	default:
		// Ignore since we seem to call analyze stack regardless.
		return &pulumirpc.AnalyzeResponse{}, nil
	}
}

func (a *analyzerServer[T]) GetAnalyzerInfo(context.Context, *pbempty.Empty) (*pulumirpc.AnalyzerInfo, error) {
	var policies []*pulumirpc.PolicyInfo

	for _, p := range a.policies {
		var required []string
		configSchemaProps := resource.NewPropertyMapFromMap(nil)
		if p.ConfigSchema != nil {
			configSchemaProps = resource.NewPropertyMap(p.ConfigSchema.Properties)
			required = p.ConfigSchema.Required
		}
		props, err := plugin.MarshalProperties(configSchemaProps,
			plugin.MarshalOptions{KeepSecrets: true})
		if err != nil {
			return nil, fmt.Errorf("failed to marshal properties for policy pack: %q: %w", a.policyPackName, err)
		}
		configSchema := pulumirpc.PolicyConfigSchema{
			Properties: props,
			Required:   required,
		}

		policies = append(policies, &pulumirpc.PolicyInfo{
			Name:             p.Name,
			Description:      p.Description,
			EnforcementLevel: pulumirpc.EnforcementLevel(p.EnforcementLevel),
			ConfigSchema:     &configSchema,
		})
	}
	return &pulumirpc.AnalyzerInfo{
		Name:           a.policyPackName,
		Policies:       policies,
		SupportsConfig: true,
		InitialConfig:  nil, /* TODO */
	}, nil
}

func (a *analyzerServer[T]) GetPluginInfo(context.Context, *pbempty.Empty) (*pulumirpc.PluginInfo, error) {
	return &pulumirpc.PluginInfo{
		Version: version.Version,
	}, nil
}

func (a *analyzerServer[T]) Configure(ctx context.Context, req *pulumirpc.ConfigureAnalyzerRequest) (*pbempty.Empty,
	error,
) {
	conf := map[string]interface{}{}
	for k, v := range req.PolicyConfig {
		pm, err := plugin.UnmarshalProperties(v.GetProperties(), plugin.MarshalOptions{
			Label:        fmt.Sprintf("%s.configure", a.policyPackName),
			KeepUnknowns: true,
		})
		conf[k] = pm.Mappable()
		if err != nil {
			return nil, err
		}
	}
	a.policyPackConfig = conf
	return &pbempty.Empty{}, nil
}
