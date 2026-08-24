// Package migrations embeds the SQL migration files so any binary can apply them.
package migrations

import (
	"embed"
	"io/fs"
	"sort"
)

//go:embed *.sql
var files embed.FS

// Names returns migration file names in lexical order.
func Names() ([]string, error) {
	entries, err := fs.ReadDir(files, ".")
	if err != nil {
		return nil, err
	}
	var names []string
	for _, e := range entries {
		if !e.IsDir() {
			names = append(names, e.Name())
		}
	}
	sort.Strings(names)
	return names, nil
}

// Read returns the contents of a named migration.
func Read(name string) ([]byte, error) {
	return files.ReadFile(name)
}

// FS exposes the raw embedded filesystem.
func FS() fs.FS { return files }
