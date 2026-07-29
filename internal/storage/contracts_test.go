package storage

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestMemoryStorage(t *testing.T) {
	require := require.New(t)

	s, err := NewStorage("memory://")
	require.NoError(err)

	require.IsType(&InMemoryStorage{}, s)
}

func TestPostgresqlStorage(t *testing.T) {
	require := require.New(t)

	s, err := NewStorage("postgresql://localhost:5432/dbname?sslmode=disable")
	require.NoError(err)

	require.IsType(&SQLStorage{}, s)
}

func TestPostgresqlConnectionStringRequiresReadWriteAndPreservesOptions(t *testing.T) {
	s, err := NewStorage("postgresql://user:p%40ss@db.example:5432/app?sslmode=disable&connect_timeout=5")
	require.NoError(t, err)

	sqlStorage := s.(*SQLStorage)
	require.Equal(t, "postgres://user:p%40ss@db.example:5432/app?connect_timeout=5&sslmode=disable&target_session_attrs=read-write", sqlStorage.connectionString)
}

func TestPostgresqlConnectionStringSupportsLegacyKeywordQuery(t *testing.T) {
	s, err := NewStorage("postgresql://user:pass@db.example:5432/app?sslmode=disable%20options='-c%20application_name=amster'")
	require.NoError(t, err)

	connectionString := s.(*SQLStorage).connectionString
	require.Contains(t, connectionString, "sslmode=disable")
	require.Contains(t, connectionString, "options=-c+application_name%3Damster")
	require.Contains(t, connectionString, "target_session_attrs=read-write")
}

func TestDefaultStorageOptions(t *testing.T) {
	require.Equal(t, time.Minute, DefaultOptions.ConnMaxLifetime)
	require.Equal(t, 30*time.Second, DefaultOptions.ConnMaxIdleTime)
}

func TestMysqlStorage(t *testing.T) {
	require := require.New(t)

	s, err := NewStorage("mysql://localhost:1234/dbname?sslmode=disable")
	require.NoError(err)

	require.IsType(&SQLStorage{}, s)
}

func TestSqliteStorage(t *testing.T) {
	require := require.New(t)

	s, err := NewStorage("sqlite3:///some/path/sqlite.db")
	require.NoError(err)

	require.IsType(&SQLStorage{}, s)
}

func TestSqliteStorageRelativePath(t *testing.T) {
	require := require.New(t)

	s, err := NewStorage("sqlite3://sqlite.db")
	require.NoError(err)

	require.IsType(&SQLStorage{}, s)
}

func TestUnknownStorage(t *testing.T) {
	require := require.New(t)

	s, err := NewStorage("foo://")
	require.Nil(s)
	require.Error(err)
	require.Equal(err.Error(), "unknown storage backend foo:")
}
