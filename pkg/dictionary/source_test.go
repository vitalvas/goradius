package dictionary

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestFileSourceLoadSingleFile(t *testing.T) {
	// Create temporary directory
	tmpDir := t.TempDir()

	// Create test YAML file
	yamlContent := `
name: "Test Dictionary"
version: "1.0"
description: "Test dictionary for unit tests"
vendors:
  9:
    name: "Cisco"
    id: 9
    description: "Cisco Systems"
attributes:
  1:
    name: "User-Name"
    type: 1
    data_type: "string"
    description: "User name for authentication"
  6:
    name: "Service-Type"
    type: 6
    data_type: "integer"
    values:
      "Login": 1
      "Framed": 2
      "Callback": 3
vsas:
  9:
    1:
      name: "Cisco-AVPair"
      type: 1
      vendor_id: 9
      data_type: "string"
      description: "Cisco AV Pair"
`

	yamlFile := filepath.Join(tmpDir, "test.yaml")
	require.NoError(t, os.WriteFile(yamlFile, []byte(yamlContent), 0644))

	// Test loading YAML file
	source := &FileSource{
		Path:   yamlFile,
		Format: "yaml",
	}

	ctx := context.Background()
	dict, err := source.Load(ctx)
	require.NoError(t, err)

	assert.Len(t, dict.Vendors, 1)
	assert.Len(t, dict.Attributes, 2)
	assert.Len(t, dict.VSAs, 1)

	// Verify vendor
	vendor, exists := dict.GetVendor(9)
	assert.True(t, exists)
	assert.Equal(t, "Cisco", vendor.Name)

	// Verify standard attribute
	attr, exists := dict.GetAttribute(1)
	assert.True(t, exists)
	assert.Equal(t, "User-Name", attr.Name)
	assert.Equal(t, DataTypeString, attr.DataType)

	// Verify service type with values
	serviceType, exists := dict.GetAttribute(6)
	assert.True(t, exists)
	assert.Equal(t, "Service-Type", serviceType.Name)
	assert.True(t, serviceType.HasValues())
	assert.Equal(t, "Login", serviceType.GetValueName(1))

	// Verify VSA
	vsa, exists := dict.GetVSA(9, 1)
	assert.True(t, exists)
	assert.Equal(t, "Cisco-AVPair", vsa.Name)
	assert.Equal(t, uint32(9), vsa.VendorID)
}

func TestFileSourceLoadJSON(t *testing.T) {
	tmpDir := t.TempDir()

	jsonContent := `{
  "name": "JSON Test Dictionary",
  "version": "1.0",
  "vendors": {
    "9": {
      "name": "Cisco",
      "id": 9
    }
  },
  "attributes": {
    "1": {
      "name": "User-Name",
      "type": 1,
      "data_type": "string"
    }
  }
}`

	jsonFile := filepath.Join(tmpDir, "test.json")
	require.NoError(t, os.WriteFile(jsonFile, []byte(jsonContent), 0644))

	source := &FileSource{
		Path:   jsonFile,
		Format: "json",
	}

	ctx := context.Background()
	dict, err := source.Load(ctx)
	require.NoError(t, err)

	// Dictionary loaded successfully
	assert.NotNil(t, dict)
}

func TestFileSourceLoadMultipleFiles(t *testing.T) {
	tmpDir := t.TempDir()

	// Create first file with vendors and one attribute
	file1Content := `
name: "Base Dictionary"
version: "1.0"
vendors:
  9:
    name: "Cisco"
    id: 9
attributes:
  1:
    name: "User-Name"
    type: 1
    data_type: "string"
`

	// Create second file with additional attributes
	file2Content := `
name: "Extension Dictionary"
version: "1.1"
attributes:
  2:
    name: "User-Password"
    type: 2
    data_type: "string"
    length: 16
vsas:
  9:
    1:
      name: "Cisco-AVPair"
      type: 1
      vendor_id: 9
      data_type: "string"
`

	file1 := filepath.Join(tmpDir, "base.yaml")
	file2 := filepath.Join(tmpDir, "extension.yaml")

	require.NoError(t, os.WriteFile(file1, []byte(file1Content), 0644))
	require.NoError(t, os.WriteFile(file2, []byte(file2Content), 0644))

	source := &FileSource{
		Paths: []string{file1, file2},
	}

	ctx := context.Background()
	dict, err := source.Load(ctx)
	require.NoError(t, err)

	// Should have merged content from both files
	assert.Len(t, dict.Vendors, 1)
	assert.Len(t, dict.Attributes, 2)
	assert.Len(t, dict.VSAs, 1)

	// Verify attributes from both files
	attr1, exists := dict.GetAttribute(1)
	assert.True(t, exists)
	assert.Equal(t, "User-Name", attr1.Name)

	attr2, exists := dict.GetAttribute(2)
	assert.True(t, exists)
	assert.Equal(t, "User-Password", attr2.Name)
	assert.Equal(t, 16, attr2.Length)
}

func TestFileSourceLoadDirectory(t *testing.T) {
	tmpDir := t.TempDir()

	// Create multiple files in directory
	files := map[string]string{
		"vendors.yaml": `
name: "Vendors"
version: "1.0"
vendors:
  9:
    name: "Cisco"
    id: 9
  311:
    name: "Microsoft"
    id: 311
`,
		"attributes.yaml": `
name: "Standard Attributes"
version: "1.0"
attributes:
  1:
    name: "User-Name"
    type: 1
    data_type: "string"
  2:
    name: "User-Password"
    type: 2
    data_type: "string"
`,
		"cisco.yaml": `
name: "Cisco VSAs"
version: "1.0"
vsas:
  9:
    1:
      name: "Cisco-AVPair"
      type: 1
      vendor_id: 9
      data_type: "string"
`,
		"readme.txt": "This should be ignored",
	}

	for filename, content := range files {
		path := filepath.Join(tmpDir, filename)
		require.NoError(t, os.WriteFile(path, []byte(content), 0644))
	}

	source := &FileSource{
		Dir: tmpDir,
	}

	ctx := context.Background()
	dict, err := source.Load(ctx)
	require.NoError(t, err)

	// Should have merged all YAML files, ignoring the .txt file
	assert.Len(t, dict.Vendors, 2)
	assert.Len(t, dict.Attributes, 2)
	assert.Len(t, dict.VSAs, 1)

	// Verify vendors from vendors.yaml
	cisco, exists := dict.GetVendor(9)
	assert.True(t, exists)
	assert.Equal(t, "Cisco", cisco.Name)

	microsoft, exists := dict.GetVendor(311)
	assert.True(t, exists)
	assert.Equal(t, "Microsoft", microsoft.Name)
}

func TestFileSourceErrors(t *testing.T) {
	tmpDir := t.TempDir()
	ctx := context.Background()

	tests := []struct {
		name   string
		source *FileSource
	}{
		{
			name:   "no files specified",
			source: &FileSource{},
		},
		{
			name: "non-existent file",
			source: &FileSource{
				Path: filepath.Join(tmpDir, "nonexistent.yaml"),
			},
		},
		{
			name: "non-existent directory",
			source: &FileSource{
				Dir: filepath.Join(tmpDir, "nonexistent"),
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := tt.source.Load(ctx)
			assert.Error(t, err)
		})
	}
}

func TestFileSourceConflictDetection(t *testing.T) {
	tmpDir := t.TempDir()

	// Create files with conflicting definitions
	file1Content := `
name: "Dict1"
version: "1.0"
vendors:
  9:
    name: "Cisco"
    id: 9
attributes:
  1:
    name: "User-Name"
    type: 1
    data_type: "string"
`

	file2Content := `
name: "Dict2"
version: "1.0"
vendors:
  9:
    name: "Juniper"  # Conflict with file1
    id: 9
`

	file1 := filepath.Join(tmpDir, "dict1.yaml")
	file2 := filepath.Join(tmpDir, "dict2.yaml")

	require.NoError(t, os.WriteFile(file1, []byte(file1Content), 0644))
	require.NoError(t, os.WriteFile(file2, []byte(file2Content), 0644))

	source := &FileSource{
		Paths: []string{file1, file2},
	}

	ctx := context.Background()
	_, err := source.Load(ctx)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "conflict")
}

func TestMultiSource(t *testing.T) {
	tmpDir := t.TempDir()

	// Create files for different sources
	file1Content := `
name: "Source1"
version: "1.0"
vendors:
  9:
    name: "Cisco"
    id: 9
attributes:
  1:
    name: "User-Name"
    type: 1
    data_type: "string"
`

	file2Content := `
name: "Source2"
version: "1.0"
attributes:
  2:
    name: "User-Password"
    type: 2
    data_type: "string"
vsas:
  9:
    1:
      name: "Cisco-AVPair"
      type: 1
      vendor_id: 9
      data_type: "string"
`

	file1 := filepath.Join(tmpDir, "source1.yaml")
	file2 := filepath.Join(tmpDir, "source2.yaml")

	require.NoError(t, os.WriteFile(file1, []byte(file1Content), 0644))
	require.NoError(t, os.WriteFile(file2, []byte(file2Content), 0644))

	source1 := &FileSource{Path: file1}
	source2 := &FileSource{Path: file2}

	multiSource := &MultiSource{
		Sources: []Source{source1, source2},
	}

	ctx := context.Background()
	dict, err := multiSource.Load(ctx)
	require.NoError(t, err)

	// Should have merged content from both sources
	assert.Len(t, dict.Vendors, 1)
	assert.Len(t, dict.Attributes, 2)
	assert.Len(t, dict.VSAs, 1)

	// Verify attributes from both sources
	attr1, exists := dict.GetAttribute(1)
	assert.True(t, exists)
	assert.Equal(t, "User-Name", attr1.Name)

	attr2, exists := dict.GetAttribute(2)
	assert.True(t, exists)
	assert.Equal(t, "User-Password", attr2.Name)

	vsa, exists := dict.GetVSA(9, 1)
	assert.True(t, exists)
	assert.Equal(t, "Cisco-AVPair", vsa.Name)
}

func TestFileSourceClose(t *testing.T) {
	source := &FileSource{}
	assert.NoError(t, source.Close())
}

func TestMultiSourceClose(t *testing.T) {
	source1 := &FileSource{}
	source2 := &FileSource{}

	multiSource := &MultiSource{
		Sources: []Source{source1, source2},
	}

	assert.NoError(t, multiSource.Close())
}
