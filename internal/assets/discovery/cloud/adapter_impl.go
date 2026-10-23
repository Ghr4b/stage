package cloud

import (
	"context"
	"database/sql"
	"os/exec"
)

type CQAdapter struct {
	CQConfigPath string
	DBPath       string
}

func (a *CQAdapter) Sync(ctx context.Context) error {
	// Execute CloudQuery sync
	cmd := exec.CommandContext(ctx, "cloudquery", "sync", a.CQConfigPath)
	return cmd.Run()
}

func (a *CQAdapter) Query(ctx context.Context, query string) ([]map[string]interface{}, error) {
	// Execute ad-hoc query against Steampipe (or SQLite DB from CQ)
	db, err := sql.Open("sqlite3", a.DBPath)
	if err != nil {
		return nil, err
	}
	defer db.Close()

	rows, err := db.QueryContext(ctx, query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	cols, _ := rows.Columns()
	var result []map[string]interface{}
	
	for rows.Next() {
		columns := make([]interface{}, len(cols))
		columnPointers := make([]interface{}, len(cols))
		for i := range columns {
			columnPointers[i] = &columns[i]
		}

		if err := rows.Scan(columnPointers...); err != nil {
			return nil, err
		}

		m := make(map[string]interface{})
		for i, colName := range cols {
			val := columnPointers[i].(*interface{})
			m[colName] = *val
		}
		result = append(result, m)
	}

	return result, nil
}

func (a *CQAdapter) ProcessEvent(ctx context.Context, eventPayload []byte) error {
	// Process CloudTrail / EventBridge payload to emit IdentitySignal
	return nil
}

var _ CloudDiscoveryAdapter = (*CQAdapter)(nil)
