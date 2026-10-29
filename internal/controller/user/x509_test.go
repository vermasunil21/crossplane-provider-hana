/*
Copyright 2026 SAP SE or an SAP affiliate company and contributors.
*/

package user

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/crossplane/crossplane-runtime/v2/pkg/test"
	xpv2 "github.com/crossplane/crossplane/apis/v2/core/v2"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/SAP/crossplane-provider-hana/apis/admin/v1alpha1"
	userclient "github.com/SAP/crossplane-provider-hana/internal/clients/hana/user"
)

const (
	x509DatabaseProvider = "DATABASE_X509_PROVIDER"
	x509ClientSubject    = "CN=client"
)

func x509Mapping(subject string) v1alpha1.X509UserMapping {
	return v1alpha1.X509UserMapping{
		X509ProviderRef: v1alpha1.X509ProviderRef{Name: x509DatabaseProvider}, SubjectName: subject,
	}
}

func x509TestUser() *v1alpha1.User {
	return &v1alpha1.User{Spec: v1alpha1.UserSpec{
		PrivilegeManagementPolicy: "lax",
		ForProvider: v1alpha1.UserParameters{
			Username: demoUser, RestrictedUser: true, Usergroup: defaultUsergroup, EnableClientConnect: true,
			Authentication: v1alpha1.Authentication{X509Providers: []v1alpha1.X509UserMapping{{
				X509ProviderRef: v1alpha1.X509ProviderRef{ProviderRef: &xpv2.Reference{Name: "kubernetes-provider"}},
				SubjectName:     x509ClientSubject,
			}}},
		},
	}}
}

func x509Resolver() *test.MockClient {
	return &test.MockClient{MockGet: test.NewMockGetFn(nil, func(obj client.Object) error {
		p, ok := obj.(*v1alpha1.X509Provider)
		if !ok {
			return fmt.Errorf("unexpected Get type %T", obj)
		}
		p.Spec.ForProvider.Name = x509DatabaseProvider
		return nil
	})}
}

func x509Observation(enabled bool, mappings []v1alpha1.X509UserMapping) *v1alpha1.UserObservation {
	return &v1alpha1.UserObservation{
		Username: new(demoUser), Usergroup: new(defaultUsergroup),
		IsPasswordLifetimeCheckEnabled: new(false), IsClientConnectEnabled: new(true),
		IsJWTEnabled: new(false), IsX509Enabled: new(enabled), X509Providers: mappings,
	}
}

func TestX509MappingReconciliationIsStable(t *testing.T) {
	cr := x509TestUser()
	changes := 0
	c := &external{kube: x509Resolver(), log: &MockLogger{}, client: mockUserClient{
		MockRead: func(_ context.Context, desired *v1alpha1.UserParameters, _ string) (*v1alpha1.UserObservation, error) {
			if desired.Authentication.X509Providers[0].ProviderRef != nil || desired.Authentication.X509Providers[0].Name != x509DatabaseProvider {
				t.Fatal("Observe must resolve providerRef before comparison")
			}
			return x509Observation(true, []v1alpha1.X509UserMapping{x509Mapping(x509ClientSubject)}), nil
		},
		MockUpdateX509Providers: func(context.Context, string, []userclient.ResolvedUserMapping, []userclient.ResolvedUserMapping) error {
			changes++
			return nil
		},
		MockEnableX509Authentication: func(context.Context, string) error {
			t.Fatal("already enabled user must not be enabled again")
			return nil
		},
	}}
	for range 3 {
		observation, err := c.Observe(context.Background(), cr)
		if err != nil || !observation.ResourceUpToDate {
			t.Fatalf("matching mappings should be up to date: %+v, %v", observation, err)
		}
		// Even an Update triggered by another property must not churn mappings.
		if _, err := c.Update(context.Background(), cr); err != nil {
			t.Fatal(err)
		}
	}
	if changes != 0 || cr.Spec.ForProvider.Authentication.X509Providers[0].ProviderRef == nil {
		t.Fatal("mapping changed or the user's desired spec was mutated")
	}
}

func TestX509EnablementDriftIsRepaired(t *testing.T) {
	cr := x509TestUser()
	enabled, calls := false, 0
	c := &external{kube: x509Resolver(), log: &MockLogger{}, client: mockUserClient{
		MockRead: func(context.Context, *v1alpha1.UserParameters, string) (*v1alpha1.UserObservation, error) {
			return x509Observation(enabled, []v1alpha1.X509UserMapping{x509Mapping(x509ClientSubject)}), nil
		},
		MockEnableX509Authentication: func(_ context.Context, username string) error {
			if username != demoUser {
				t.Fatalf("wrong user: %s", username)
			}
			calls++
			enabled = true
			return nil
		},
		MockUpdateX509Providers: func(context.Context, string, []userclient.ResolvedUserMapping, []userclient.ResolvedUserMapping) error {
			t.Fatal("enablement-only drift must not change mappings")
			return nil
		},
	}}
	for range 2 { // Repair again if X.509 is later disabled out of band.
		enabled = false
		observation, err := c.Observe(context.Background(), cr)
		if err != nil || observation.ResourceUpToDate {
			t.Fatalf("disabled X.509 must require Update: %+v, %v", observation, err)
		}
		if ready := cr.GetCondition(xpv2.Unavailable().Type); ready.Status != "False" {
			t.Fatalf("disabled X.509 must not be Ready: %+v", ready)
		}
		if _, err := c.Update(context.Background(), cr); err != nil {
			t.Fatal(err)
		}
		if cr.Status.AtProvider.IsX509Enabled == nil || !*cr.Status.AtProvider.IsX509Enabled {
			t.Fatal("successful enablement must be reflected in status")
		}
		observation, err = c.Observe(context.Background(), cr)
		if err != nil || !observation.ResourceUpToDate {
			t.Fatalf("repaired user must converge: %+v, %v", observation, err)
		}
		if ready := cr.GetCondition(xpv2.Available().Type); ready.Status != "True" {
			t.Fatalf("enabled user should be Ready: %+v", ready)
		}
	}
	if calls != 2 {
		t.Fatalf("expected two repairs, got %d", calls)
	}
}

func TestX509EnablementFailure(t *testing.T) {
	cr := x509TestUser()
	cr.Status.AtProvider = *x509Observation(false, []v1alpha1.X509UserMapping{x509Mapping(x509ClientSubject)})
	boom := errors.New("permission denied")
	c := &external{kube: x509Resolver(), log: &MockLogger{}, client: mockUserClient{
		MockEnableX509Authentication: func(context.Context, string) error { return boom },
	}}
	if _, err := c.Update(context.Background(), cr); !errors.Is(err, boom) {
		t.Fatalf("enablement error must propagate: %v", err)
	}
	if *cr.Status.AtProvider.IsX509Enabled {
		t.Fatal("failed enablement must not be reported as enabled")
	}
}

func TestAddingX509MappingEnablesAuthentication(t *testing.T) {
	cr := x509TestUser()
	cr.Status.AtProvider = *x509Observation(false, nil)
	var operations []string
	c := &external{kube: x509Resolver(), log: &MockLogger{}, client: mockUserClient{
		MockUpdateX509Providers: func(_ context.Context, username string, add, remove []userclient.ResolvedUserMapping) error {
			if username != demoUser || len(add) != 1 || len(remove) != 0 || add[0].Name != x509DatabaseProvider || add[0].SubjectName != x509ClientSubject {
				t.Fatalf("unexpected identity registration: user=%s add=%+v remove=%+v", username, add, remove)
			}
			operations = append(operations, "mapping")
			return nil
		},
		MockEnableX509Authentication: func(context.Context, string) error {
			operations = append(operations, "enable")
			return nil
		},
	}}
	if _, err := c.Update(context.Background(), cr); err != nil {
		t.Fatal(err)
	}
	if len(operations) != 2 || operations[0] != "mapping" || operations[1] != "enable" {
		t.Fatalf("must register mappings before enabling authentication: %v", operations)
	}
}

func TestMappingFailureDoesNotEnableX509(t *testing.T) {
	cr := x509TestUser()
	cr.Status.AtProvider = *x509Observation(false, nil)
	boom := errors.New("identity registration failed")
	c := &external{kube: x509Resolver(), log: &MockLogger{}, client: mockUserClient{
		MockUpdateX509Providers: func(context.Context, string, []userclient.ResolvedUserMapping, []userclient.ResolvedUserMapping) error {
			return boom
		},
		MockEnableX509Authentication: func(context.Context, string) error {
			t.Fatal("must not enable X.509 after failed mapping registration")
			return nil
		},
	}}
	if _, err := c.Update(context.Background(), cr); !errors.Is(err, boom) {
		t.Fatalf("mapping error must propagate: %v", err)
	}
}

func TestRemovingX509MappingsDoesNotDisableAuthentication(t *testing.T) {
	cr := x509TestUser()
	cr.Spec.ForProvider.Authentication.X509Providers = nil
	cr.Status.AtProvider = *x509Observation(true, []v1alpha1.X509UserMapping{x509Mapping(x509ClientSubject)})
	removed := 0
	c := &external{kube: x509Resolver(), log: &MockLogger{}, client: mockUserClient{
		MockEnableX509Authentication: func(context.Context, string) error {
			t.Fatal("empty desired mappings must not change enablement")
			return nil
		},
		MockUpdateX509Providers: func(_ context.Context, _ string, add, remove []userclient.ResolvedUserMapping) error {
			if len(add) != 0 || len(remove) != 1 || remove[0].Name != x509DatabaseProvider {
				t.Fatalf("unexpected mapping diff: add=%+v remove=%+v", add, remove)
			}
			removed++
			return nil
		},
	}}
	if _, err := c.Update(context.Background(), cr); err != nil {
		t.Fatal(err)
	}
	if removed != 1 || !*cr.Status.AtProvider.IsX509Enabled {
		t.Fatal("remove must preserve the authentication mechanism")
	}
}

func TestResolveX509ProviderNames(t *testing.T) {
	for name, mapping := range map[string]v1alpha1.X509UserMapping{
		"explicit":      x509Mapping(x509ClientSubject),
		"wildcard":      {X509ProviderRef: v1alpha1.X509ProviderRef{ProviderRef: &xpv2.Reference{Name: "kubernetes-provider"}}},
		"explicit wins": {X509ProviderRef: v1alpha1.X509ProviderRef{Name: x509DatabaseProvider, ProviderRef: &xpv2.Reference{Name: "unused"}}, SubjectName: x509ClientSubject},
	} {
		t.Run(name, func(t *testing.T) {
			cr := x509TestUser()
			cr.Spec.ForProvider.Authentication.X509Providers = []v1alpha1.X509UserMapping{mapping}
			kube := x509Resolver()
			if mapping.Name != "" {
				kube.MockGet = test.NewMockGetFn(errors.New("explicit name must not access Kubernetes"))
			}
			c := &external{kube: kube, log: &MockLogger{}, client: mockUserClient{}}
			desired, err := c.buildDesiredParameters(context.Background(), cr)
			if err != nil {
				t.Fatal(err)
			}
			subject := mapping.SubjectName
			if subject == "" {
				subject = "ANY"
			}
			if !isX509MappingsUpToDate(x509Observation(true, []v1alpha1.X509UserMapping{x509Mapping(subject)}), desired) {
				t.Fatal("resolved database name/subject must match observed mapping")
			}
		})
	}
}

func TestResolveX509ProviderErrors(t *testing.T) {
	for name, mapping := range map[string]v1alpha1.X509UserMapping{
		"no name or reference": {SubjectName: x509ClientSubject},
		"missing provider":     {X509ProviderRef: v1alpha1.X509ProviderRef{ProviderRef: &xpv2.Reference{Name: "missing"}}, SubjectName: x509ClientSubject},
	} {
		t.Run(name, func(t *testing.T) {
			cr := x509TestUser()
			cr.Spec.ForProvider.Authentication.X509Providers = []v1alpha1.X509UserMapping{mapping}
			c := &external{kube: &test.MockClient{MockGet: test.NewMockGetFn(errors.New("not found"))}, log: &MockLogger{}, client: mockUserClient{}}
			if _, err := c.buildDesiredParameters(context.Background(), cr); err == nil {
				t.Fatal("unresolvable mapping must return an error")
			}
			if _, err := c.Observe(context.Background(), cr); err == nil {
				t.Fatal("Observe must reject an unresolvable mapping before reading the user")
			}
		})
	}
}

func TestX509EnabledDesiredState(t *testing.T) {
	for name, tc := range map[string]struct {
		configured bool
		enabled    *bool
		upToDate   bool
	}{
		"configured and enabled":    {configured: true, enabled: new(true), upToDate: true},
		"configured and disabled":   {configured: true, enabled: new(false)},
		"configured and unknown":    {configured: true},
		"unconfigured and enabled":  {enabled: new(true), upToDate: true},
		"unconfigured and disabled": {enabled: new(false), upToDate: true},
		"unconfigured and unknown":  {upToDate: true},
	} {
		t.Run(name, func(t *testing.T) {
			desired := &v1alpha1.UserParameters{}
			if tc.configured {
				desired.Authentication.X509Providers = []v1alpha1.X509UserMapping{x509Mapping(x509ClientSubject)}
			}
			observed := &v1alpha1.UserObservation{IsX509Enabled: tc.enabled}
			if got := isX509EnabledUpToDate(observed, desired); got != tc.upToDate {
				t.Fatalf("got upToDate=%v, want %v", got, tc.upToDate)
			}
		})
	}
}
