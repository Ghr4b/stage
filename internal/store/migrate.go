package store

import (
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// RunMigrations executes all .sql files in the migrations directory in order.
func RunMigrations(db *sql.DB, migrationsDir string) error {
	entries, err := os.ReadDir(migrationsDir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil // no migrations directory is fine
		}
		return fmt.Errorf("failed to read migrations directory: %w", err)
	}

	var files []string
	for _, e := range entries {
		if !e.IsDir() && strings.HasSuffix(e.Name(), ".sql") {
			files = append(files, filepath.Join(migrationsDir, e.Name()))
		}
	}
	sort.Strings(files)

	for _, f := range files {
		content, err := os.ReadFile(f)
		if err != nil {
			return fmt.Errorf("failed to read migration %s: %w", f, err)
		}

		statements := splitStatements(string(content))
		for _, stmt := range statements {
			stmt = strings.TrimSpace(stmt)
			if stmt == "" {
				continue
			}
			if _, err := db.Exec(stmt); err != nil {
				// Log but don't fail on "already exists" errors
				if strings.Contains(err.Error(), "already exists") ||
					strings.Contains(err.Error(), "duplicate") ||
					strings.Contains(err.Error(), "does not exist") {
					continue
				}
				return fmt.Errorf("migration %s failed: %w\nStatement: %s", f, err, stmt)
			}
		}
		fmt.Printf("  [Migration] Applied %s\n", filepath.Base(f))
	}
	return nil
}

// splitStatements splits a SQL file into individual statements by semicolons.
func splitStatements(content string) []string {
	var statements []string
	var current strings.Builder
	inSingleQuote := false
	inDoubleQuote := false

	for i := 0; i < len(content); i++ {
		ch := content[i]

		if ch == '\'' && !inDoubleQuote {
			if i+1 < len(content) && content[i+1] == '\'' {
				current.WriteByte(ch)
				current.WriteByte(ch)
				i++
				continue
			}
			inSingleQuote = !inSingleQuote
			current.WriteByte(ch)
			continue
		}

		if ch == '"' && !inSingleQuote {
			inDoubleQuote = !inDoubleQuote
			current.WriteByte(ch)
			continue
		}

		if ch == ';' && !inSingleQuote && !inDoubleQuote {
			stmt := strings.TrimSpace(current.String())
			if stmt != "" {
				statements = append(statements, stmt)
			}
			current.Reset()
			continue
		}

		current.WriteByte(ch)
	}

	stmt := strings.TrimSpace(current.String())
	if stmt != "" {
		statements = append(statements, stmt)
	}

	return statements
}
