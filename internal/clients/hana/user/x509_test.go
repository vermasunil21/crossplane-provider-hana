/*
Copyright 2026 SAP SE or an SAP affiliate company and contributors.
*/

package user

import (
	"context"
	"errors"
	"regexp"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"

	"github.com/SAP/crossplane-provider-hana/apis/admin/v1alpha1"
)

func TestCreateEnablesX509AfterMappings(t *testing.T) {
	for _, restricted := range []bool{false, true} {
		name := "ordinary"
		if restricted {
			name = "restricted"
		}
		t.Run(name, func(t *testing.T) {
			db, mock, err := sqlmock.New()
			if err != nil {
				t.Fatal(err)
			}
			defer db.Close()
			createSQL := "CREATE USER CERT_USER"
			if restricted {
				createSQL = "CREATE RESTRICTED USER CERT_USER"
			}
			mock.ExpectExec(regexp.QuoteMeta(createSQL)).WillReturnResult(sqlmock.NewResult(0, 0))
			mock.ExpectExec(regexp.QuoteMeta("ALTER USER CERT_USER ADD IDENTITY 'CN=client' FOR X509 PROVIDER CERT_PROVIDER")).WillReturnResult(sqlmock.NewResult(0, 0))
			mock.ExpectExec(regexp.QuoteMeta("ALTER USER CERT_USER ADD IDENTITY 'CN=backup' FOR X509 PROVIDER BACKUP_PROVIDER")).WillReturnResult(sqlmock.NewResult(0, 0))
			mock.ExpectExec(regexp.QuoteMeta(`ALTER USER "CERT_USER" ENABLE X509`)).WillReturnResult(sqlmock.NewResult(0, 0))
			if restricted {
				mock.ExpectExec(regexp.QuoteMeta("ALTER USER CERT_USER ENABLE CLIENT CONNECT")).WillReturnResult(sqlmock.NewResult(0, 0))
			}
			parameters := &v1alpha1.UserParameters{Username: "CERT_USER", RestrictedUser: restricted, EnableClientConnect: true}
			c := New(db, "ADMIN")
			if err := c.Create(context.Background(), parameters, "", []ResolvedUserMapping{
				{Name: "CERT_PROVIDER", SubjectName: "CN=client"},
				{Name: "BACKUP_PROVIDER", SubjectName: "CN=backup"},
			}, nil); err != nil {
				t.Fatal(err)
			}
			if err := mock.ExpectationsWereMet(); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestCreateDoesNotEnableX509WithoutMappings(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	mock.ExpectExec("CREATE USER BASIC_USER").WillReturnResult(sqlmock.NewResult(0, 0))
	c := New(db, "ADMIN")
	if err := c.Create(context.Background(), &v1alpha1.UserParameters{Username: "BASIC_USER", EnableClientConnect: true}, "", nil, nil); err != nil {
		t.Fatal(err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestEnableX509Authentication(t *testing.T) {
	for _, sqlErr := range []error{nil, errors.New("permission denied")} {
		db, mock, err := sqlmock.New()
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { db.Close() })
		expect := mock.ExpectExec(regexp.QuoteMeta(`ALTER USER "CERT""USER" ENABLE X509`))
		if sqlErr == nil {
			expect.WillReturnResult(sqlmock.NewResult(0, 0))
		} else {
			expect.WillReturnError(sqlErr)
		}
		c := New(db, "ADMIN")
		if err := c.EnableX509Authentication(context.Background(), `CERT"USER`); !errors.Is(err, sqlErr) {
			t.Fatalf("want %v, got %v", sqlErr, err)
		}
		if err := mock.ExpectationsWereMet(); err != nil {
			t.Fatal(err)
		}
	}
}

func TestCreatePropagatesX509EnablementFailure(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	boom := errors.New("permission denied")
	mock.ExpectExec("CREATE USER CERT_USER").WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectExec("ADD IDENTITY").WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectExec("ENABLE X509").WillReturnError(boom)
	c := New(db, "ADMIN")
	if err := c.Create(context.Background(), &v1alpha1.UserParameters{Username: "CERT_USER"}, "", []ResolvedUserMapping{{Name: "P", SubjectName: "CN=client"}}, nil); !errors.Is(err, boom) {
		t.Fatalf("want enablement error, got %v", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestReadObservesX509Enablement(t *testing.T) {
	for _, tc := range []struct {
		name    string
		enabled bool
		err     error
	}{
		{name: "enabled", enabled: true},
		{name: "disabled with existing mapping"},
		{name: "query failure", err: errors.New("catalog access denied")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			db, mock, err := sqlmock.New()
			if err != nil {
				t.Fatal(err)
			}
			defer db.Close()
			mock.ExpectQuery("SELECT USER_NAME,").WithArgs("CERT_USER").WillReturnRows(
				sqlmock.NewRows([]string{"USER_NAME", "USERGROUP_NAME", "CREATE_TIME", "LAST_PASSWORD_CHANGE_TIME", "IS_RESTRICTED", "IS_PASSWORD_LIFETIME_CHECK_ENABLED", "IS_PASSWORD_ENABLED", "IS_CLIENT_CONNECT_ENABLED"}).
					AddRow("CERT_USER", "DEFAULT", testTime.Time, testTime.Time, true, false, false, true))
			mock.ExpectQuery("FROM SYS.USER_PARAMETERS").WithArgs("CERT_USER").WillReturnRows(sqlmock.NewRows([]string{"USER_NAME", "PARAMETER", "VALUE"}))
			mock.ExpectQuery("FROM GRANTED_PRIVILEGES").WithArgs("USER", "CERT_USER").WillReturnRows(sqlmock.NewRows([]string{"OBJECT_TYPE", "PRIVILEGE", "SCHEMA_NAME", "OBJECT_NAME", "IS_GRANTABLE"}))
			mock.ExpectQuery("FROM GRANTED_ROLES").WithArgs("USER", "CERT_USER").WillReturnRows(sqlmock.NewRows([]string{"ROLE_SCHEMA_NAME", "ROLE_NAME", "IS_GRANTABLE"}))
			mock.ExpectQuery("FROM X509_USER_MAPPINGS").WithArgs("CERT_USER").WillReturnRows(
				sqlmock.NewRows([]string{"X509_PROVIDER_NAME", "SUBJECT_NAME"}).AddRow("CERT_PROVIDER", "CN=client"))
			expect := mock.ExpectQuery("SELECT IS_X509_ENABLED").WithArgs("CERT_USER")
			if tc.err != nil {
				expect.WillReturnError(tc.err)
			} else {
				expect.WillReturnRows(sqlmock.NewRows([]string{"IS_X509_ENABLED"}).AddRow(tc.enabled))
				mock.ExpectQuery("FROM SYS.JWT_USER_MAPPINGS").WithArgs("CERT_USER").WillReturnRows(sqlmock.NewRows([]string{"JWT_PROVIDER_NAME", "EXTERNAL_IDENTITY"}))
				mock.ExpectQuery("SELECT IS_JWT_ENABLED").WithArgs("CERT_USER").WillReturnRows(sqlmock.NewRows([]string{"IS_JWT_ENABLED"}).AddRow(false))
			}
			c := New(db, "ADMIN")
			observed, err := c.Read(context.Background(), &v1alpha1.UserParameters{Username: "CERT_USER"}, "")
			if !errors.Is(err, tc.err) {
				t.Fatalf("want %v, got %v", tc.err, err)
			}
			if tc.err == nil && (observed.IsX509Enabled == nil || *observed.IsX509Enabled != tc.enabled) {
				t.Fatal("read must reflect the actual authentication flag, not infer it from mappings")
			}
			if tc.err != nil && observed.IsX509Enabled != nil {
				t.Fatal("failed observation must not claim X.509 is enabled")
			}
			if err := mock.ExpectationsWereMet(); err != nil {
				t.Fatal(err)
			}
		})
	}
}
