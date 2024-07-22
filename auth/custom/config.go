package custom

import (
	"context"
	"database/sql"
	"fmt"
	"github.com/viant/scy"
	"github.com/viant/scy/cred"
	"github.com/viant/sqlparser"
	"github.com/viant/sqlparser/expr"
	"github.com/viant/sqlparser/node"
	"reflect"
	"strings"
)

// Config represents the custom configuration
type (
	Config struct {
		AuthSQL           string
		AuthConnector     string
		IdentitySQL       string //maps identifier to subject
		IdentityConnector string
		MaxAttempts       int
		insertSQL         string
		updateSQL         string
	}

	Connector interface {
		DB() (*sql.DB, error)
	}

	sqlConnector struct {
		Driver string
		DSN    string
		Secret *scy.Resource
	}
)

// NewConnector creates a connector
func NewConnector(driver, dsn string, secret *scy.Resource) *sqlConnector {
	return &sqlConnector{
		Driver: driver,
		DSN:    dsn,
		Secret: secret,
	}
}

// DB returns a new sql.DB
func (c *sqlConnector) DB(ctx context.Context) (*sql.DB, error) {
	scySrv := scy.New()
	dsn := c.DSN
	if secretResource := c.Secret; secretResource != nil {
		secretResource.SetTarget(reflect.TypeOf(cred.Basic{}))
		secret, err := scySrv.Load(ctx, secretResource)
		if err != nil {
			return nil, err

		}
		dsn = secret.Expand(dsn)
	}
	return sql.Open(c.Driver, dsn)
}

func (c *Config) EnsureSQL() error {
	if c.insertSQL != "" {
		return nil
	}
	return c.buildSQL()
}

func (c *Config) buildSQL() error {
	query, err := sqlparser.ParseQuery(c.AuthSQL)
	if err != nil {
		return err
	}

	var idColumn, passwordColumn, lockedColumn, attemptsColumn string
	for _, item := range query.List {
		name := sqlparser.Stringify(item.Expr)
		name = trimNamespace(name)
		alias := item.Alias
		if alias == "" {
			alias = name
		}
		switch alias {
		case "id":
			idColumn = name
		case "password":
			passwordColumn = name
		case "locked":
			lockedColumn = name
		case "attempts":
			attemptsColumn = name
		}
	}
	table := sqlparser.Stringify(query.From.X)
	if idColumn == "" {
		sqlparser.Traverse(query.Qualify.X, func(node node.Node) bool {
			binary, ok := node.(*expr.Binary)
			if ok && binary.Op == "=" {
				idColumn = trimNamespace(sqlparser.Stringify(binary.X))
			}
			return true
		})
	}
	if passwordColumn == "" {
		return fmt.Errorf("password column was empty")
	}
	c.insertSQL = "INSERT INTO " + table + " (" + idColumn + ", " + passwordColumn + ") VALUES (?, ?)"
	c.updateSQL = "UPDATE " + table + " SET " + passwordColumn + " = ? WHERE " + idColumn + " = ?"

	authBuilder := strings.Builder{}
	authBuilder.WriteString("SELECT ")
	authBuilder.WriteString(passwordColumn)
	authBuilder.WriteString(", ")
	if lockedColumn == "" {
		lockedColumn = "0 AS locked"
	}
	authBuilder.WriteString(lockedColumn)
	authBuilder.WriteString(", ")
	if attemptsColumn == "" {
		attemptsColumn = "0 AS attempts"
	}
	authBuilder.WriteString(attemptsColumn)
	authBuilder.WriteString(" FROM " + table + " WHERE " + idColumn + " = ?")
	c.AuthSQL = authBuilder.String()
	return nil
}

func trimNamespace(name string) string {
	if index := strings.Index(name, "."); index != -1 {
		name = name[index+1:]
	}
	return name
}
