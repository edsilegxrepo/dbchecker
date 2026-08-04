package database

import (
	"context"
	"errors"
	"fmt"
	"time"

	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"

	"github.com/edsilegxrepo/dbchecker/config"
)

func init() {
	RegisterDriver("mongodb", func() DB { return &MongoDB{} })
}

// MongoDB implements the DB interface for MongoDB using the v2 driver.
type MongoDB struct {
	client   *mongo.Client
	database string
}

// Connect establishes a connection to MongoDB using the provided configuration.
// It uses the v2 driver pattern where mongo.Connect takes only options.
func (m *MongoDB) Connect(ctx context.Context, cfg config.DatabaseConfig, decryptedPassword string) error {
	uri := fmt.Sprintf("mongodb://%s:%d", cfg.Host, cfg.Port)
	clientOptions := options.Client().ApplyURI(uri)

	if cfg.User != "" {
		creds := options.Credential{
			Username: cfg.User,
			Password: decryptedPassword,
		}
		clientOptions.SetAuth(creds)
	}

	tlsConfig, err := buildTLSConfig(cfg.TLSMode, cfg.Host, cfg.RootCertPath, cfg.ClientCertPath, cfg.ClientKeyPath)
	if err != nil {
		return err
	}
	if tlsConfig != nil {
		clientOptions.SetTLSConfig(tlsConfig)
	}

	client, err := mongo.Connect(clientOptions)
	if err != nil {
		return fmt.Errorf("mongodb connection failed: %w", err)
	}
	m.client = client
	m.database = cfg.Name
	return nil
}

func (m *MongoDB) Ping(ctx context.Context) error {
	if m.client == nil {
		return errors.New("mongodb client not initialized")
	}
	return m.client.Ping(ctx, nil)
}

// HealthCheck executes a custom MongoDB command JSON string (e.g. `{"dbStats": 1}`) if provided,
// or defaults to listing database collection names.
func (m *MongoDB) HealthCheck(ctx context.Context, query string) error {
	if m.client == nil {
		return errors.New("mongodb client not initialized")
	}
	db := m.client.Database(m.database)

	if query != "" {
		var cmd bson.D
		if err := bson.UnmarshalExtJSON([]byte(query), true, &cmd); err != nil || len(cmd) == 0 {
			return fmt.Errorf("invalid mongodb health_query json syntax: %w", err)
		}
		res := db.RunCommand(ctx, cmd)
		if err := res.Err(); err != nil {
			return fmt.Errorf("mongodb custom command failed: %w", err)
		}
		return nil
	}

	_, err := db.ListCollectionNames(ctx, bson.D{})
	if err != nil {
		return fmt.Errorf("mongodb list collections failed: %w", err)
	}
	return nil
}

// Close disconnects from MongoDB with a 5-second timeout.
// Uses bounded timeout instead of context.Background() to prevent indefinite blocking.
func (m *MongoDB) Close() error {
	if m.client == nil {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return m.client.Disconnect(ctx)
}
