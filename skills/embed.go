// Package skills embeds the portable runtime guidance shipped with Mechanize.
package skills

import (
	"embed"
	"io/fs"

	"github.com/viant/datly/mcp/resource"
)

//go:embed mechanize-*
var Files embed.FS

const Entrypoint = "skill://mechanize-desktop/SKILL.md"

// Folders declares each embedded skill explicitly for a Datly MCP host.
// Only the embedded public guidance is exposed, never repository working notes.
func Folders() ([]resource.Folder, error) {
	entries, err := fs.ReadDir(Files, ".")
	if err != nil {
		return nil, err
	}
	var result []resource.Folder
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		name := entry.Name()
		result = append(result, resource.Folder{
			Namespace: "mechanize-skills", Root: name,
			URIPrefix: "skill://" + name + "/", FS: Files, Skills: []string{"."},
		})
	}
	return result, nil
}
