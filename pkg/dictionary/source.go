package dictionary

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

// FileSource loads dictionaries from local files (YAML or JSON)
type FileSource struct {
	// Path specifies a single file path to load
	Path string

	// Paths specifies multiple file paths to load and merge
	Paths []string

	// Dir specifies a directory to scan for dictionary files
	Dir string

	// Format specifies the file format ("yaml", "json", or "auto")
	Format string
}

// MultiSource combines multiple dictionary sources
type MultiSource struct {
	Sources []Source
}

// Load loads the dictionary from file(s)
func (fs *FileSource) Load(ctx context.Context) (*Dictionary, error) {
	var filePaths []string

	// Determine which files to load
	if fs.Path != "" {
		filePaths = append(filePaths, fs.Path)
	}

	if len(fs.Paths) > 0 {
		filePaths = append(filePaths, fs.Paths...)
	}

	if fs.Dir != "" {
		dirFiles, err := fs.scanDirectory(fs.Dir)
		if err != nil {
			return nil, fmt.Errorf("failed to scan directory %s: %w", fs.Dir, err)
		}
		filePaths = append(filePaths, dirFiles...)
	}

	if len(filePaths) == 0 {
		return nil, fmt.Errorf("no files specified to load")
	}

	// Load and merge dictionaries
	var merged *Dictionary
	for _, path := range filePaths {
		dict, err := fs.loadSingleFile(ctx, path)
		if err != nil {
			return nil, fmt.Errorf("failed to load file %s: %w", path, err)
		}

		if merged == nil {
			merged = dict
		} else {
			if err := fs.mergeDictionaries(merged, dict); err != nil {
				return nil, fmt.Errorf("failed to merge dictionary from %s: %w", path, err)
			}
		}
	}

	return merged, nil
}

// mergeDictionaries merges a source dictionary into the target dictionary
func (fs *FileSource) mergeDictionaries(target, source *Dictionary) error {
	// Merge vendors with conflict detection
	for id, vendor := range source.Vendors {
		if existing, exists := target.Vendors[id]; exists {
			if existing.Name != vendor.Name {
				return fmt.Errorf("vendor conflict: vendor ID %d defined as both '%s' and '%s'", id, existing.Name, vendor.Name)
			}
		} else {
			target.Vendors[id] = vendor
		}
	}

	// Merge attributes with conflict detection
	for id, attr := range source.Attributes {
		if existing, exists := target.Attributes[id]; exists {
			if existing.Name != attr.Name || existing.DataType != attr.DataType {
				return fmt.Errorf("attribute conflict: attribute ID %d defined differently", id)
			}
		} else {
			target.Attributes[id] = attr
		}
	}

	// Merge VSAs with conflict detection
	for vendorID, vsaMap := range source.VSAs {
		if target.VSAs[vendorID] == nil {
			target.VSAs[vendorID] = make(map[uint8]*AttributeDefinition)
		}
		for attrID, attr := range vsaMap {
			if existing, exists := target.VSAs[vendorID][attrID]; exists {
				if existing.Name != attr.Name || existing.DataType != attr.DataType {
					return fmt.Errorf("VSA conflict: vendor %d attribute ID %d defined differently", vendorID, attrID)
				}
			} else {
				target.VSAs[vendorID][attrID] = attr
			}
		}
	}

	return nil
}

// Close closes the file source (no-op for file sources)
func (fs *FileSource) Close() error {
	return nil
}

// Load loads dictionaries from all sources and merges them
func (ms *MultiSource) Load(ctx context.Context) (*Dictionary, error) {
	if len(ms.Sources) == 0 {
		return nil, fmt.Errorf("no sources specified")
	}

	var merged *Dictionary
	for i, source := range ms.Sources {
		dict, err := source.Load(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to load from source %d: %w", i, err)
		}

		if merged == nil {
			merged = dict
		} else {
			if err := ms.mergeDictionaries(merged, dict); err != nil {
				return nil, fmt.Errorf("failed to merge dictionary from source %d: %w", i, err)
			}
		}
	}

	return merged, nil
}

// mergeDictionaries merges a source dictionary into the target dictionary
func (ms *MultiSource) mergeDictionaries(target, source *Dictionary) error {
	// Merge vendors with conflict detection
	for id, vendor := range source.Vendors {
		if existing, exists := target.Vendors[id]; exists {
			if existing.Name != vendor.Name {
				return fmt.Errorf("vendor conflict: vendor ID %d defined as both '%s' and '%s'", id, existing.Name, vendor.Name)
			}
		} else {
			target.Vendors[id] = vendor
		}
	}

	// Merge attributes with conflict detection
	for id, attr := range source.Attributes {
		if existing, exists := target.Attributes[id]; exists {
			if existing.Name != attr.Name || existing.DataType != attr.DataType {
				return fmt.Errorf("attribute conflict: attribute ID %d defined differently", id)
			}
		} else {
			target.Attributes[id] = attr
		}
	}

	// Merge VSAs with conflict detection
	for vendorID, vsaMap := range source.VSAs {
		if target.VSAs[vendorID] == nil {
			target.VSAs[vendorID] = make(map[uint8]*AttributeDefinition)
		}
		for attrID, attr := range vsaMap {
			if existing, exists := target.VSAs[vendorID][attrID]; exists {
				if existing.Name != attr.Name || existing.DataType != attr.DataType {
					return fmt.Errorf("VSA conflict: vendor %d attribute ID %d defined differently", vendorID, attrID)
				}
			} else {
				target.VSAs[vendorID][attrID] = attr
			}
		}
	}

	return nil
}

// Close closes all sources
func (ms *MultiSource) Close() error {
	var errors []string
	for i, source := range ms.Sources {
		if err := source.Close(); err != nil {
			errors = append(errors, fmt.Sprintf("source %d: %v", i, err))
		}
	}

	if len(errors) > 0 {
		return fmt.Errorf("errors closing sources: %s", strings.Join(errors, "; "))
	}

	return nil
}

// Helper methods for FileSource

func (fs *FileSource) scanDirectory(dir string) ([]string, error) {
	var files []string

	err := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		if info.IsDir() {
			return nil
		}

		// Check for dictionary files
		ext := strings.ToLower(filepath.Ext(path))
		if ext == ".yaml" || ext == ".yml" || ext == ".json" {
			files = append(files, path)
		}

		return nil
	})

	return files, err
}

func (fs *FileSource) loadSingleFile(_ context.Context, path string) (*Dictionary, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("failed to open file: %w", err)
	}
	defer file.Close()

	data, err := io.ReadAll(file)
	if err != nil {
		return nil, fmt.Errorf("failed to read file: %w", err)
	}

	format := fs.Format
	if format == "" || format == "auto" {
		format = fs.detectFormat(path, data)
	}

	var dict Dictionary
	switch format {
	case "yaml", "yml":
		if err := yaml.Unmarshal(data, &dict); err != nil {
			return nil, fmt.Errorf("failed to parse YAML: %w", err)
		}
	case "json":
		if err := json.Unmarshal(data, &dict); err != nil {
			return nil, fmt.Errorf("failed to parse JSON: %w", err)
		}
	default:
		return nil, fmt.Errorf("unsupported format: %s", format)
	}

	// Initialize maps if nil
	if dict.Vendors == nil {
		dict.Vendors = make(map[uint32]*VendorDefinition)
	}
	if dict.Attributes == nil {
		dict.Attributes = make(map[uint8]*AttributeDefinition)
	}
	if dict.VSAs == nil {
		dict.VSAs = make(map[uint32]map[uint8]*AttributeDefinition)
	}

	return &dict, nil
}

func (fs *FileSource) detectFormat(path string, data []byte) string {
	ext := strings.ToLower(filepath.Ext(path))

	switch ext {
	case ".yaml", ".yml":
		return "yaml"
	case ".json":
		return "json"
	default:
		// Try to detect from content
		trimmed := strings.TrimSpace(string(data))
		if strings.HasPrefix(trimmed, "{") || strings.HasPrefix(trimmed, "[") {
			return "json"
		}
		return "yaml" // Default to YAML
	}
}
