package normalize

import (
	"encoding/json"
	"fmt"
	"github.com/santhosh-tekuri/jsonschema/v5"
	"tijeri/internal/models"
)

var schemaCompiler *jsonschema.Compiler
var findingSchema *jsonschema.Schema

func init() {
	schemaCompiler = jsonschema.NewCompiler()
	schemaCompiler.Draft = jsonschema.Draft7
}

// ValidateFinding validates a models.Finding against the JSON schema.
func ValidateFinding(schemaPath string, finding models.Finding) error {
	if findingSchema == nil {
		sch, err := schemaCompiler.Compile(schemaPath)
		if err != nil {
			return fmt.Errorf("failed to compile schema: %w", err)
		}
		findingSchema = sch
	}

	findingJSON, err := json.Marshal(finding)
	if err != nil {
		return fmt.Errorf("failed to marshal finding: %w", err)
	}

	var parsed interface{}
	if err := json.Unmarshal(findingJSON, &parsed); err != nil {
		return fmt.Errorf("failed to unmarshal for validation: %w", err)
	}

	if err := findingSchema.Validate(parsed); err != nil {
		return fmt.Errorf("schema validation failed: %w", err)
	}

	return nil
}
