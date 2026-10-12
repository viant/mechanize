package skills

import (
	"context"
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"testing/fstest"

	skillformat "github.com/viant/mcp-protocol/extension/skills"
)

type LocalGuide struct {
	Compiled       *skillformat.Static
	EntrypointText string
}

var ErrLocalSkills = errors.New("local skill directory or content is unavailable")
var localSkillName = regexp.MustCompile(`^[a-z][a-z0-9-]{0,63}$`)

// LoadLocal seals configured, user-owned guidance into MCP compiler snapshots.
// The roots come from host enrollment, never an MCP URI or caller path. Root
// confinement and symlink rejection keep Vault/credential files out of reads.
func LoadLocal(ctx context.Context, directories []string) ([]LocalGuide, error) {
	if len(directories) > 8 {
		return nil, ErrLocalSkills
	}
	var guides []LocalGuide
	for _, directory := range directories {
		canonical, err := filepath.EvalSymlinks(directory)
		if err != nil || !filepath.IsAbs(directory) || canonical != filepath.Clean(directory) {
			return nil, ErrLocalSkills
		}
		info, err := os.Stat(directory)
		if err != nil || !info.IsDir() || info.Mode().Perm()&0022 != 0 {
			return nil, ErrLocalSkills
		}
		root, err := os.OpenRoot(directory)
		if err != nil {
			return nil, ErrLocalSkills
		}
		loaded, err := loadLocalRoot(ctx, root)
		root.Close()
		if err != nil {
			return nil, ErrLocalSkills
		}
		guides = append(guides, loaded...)
		if len(guides) > 64 {
			return nil, ErrLocalSkills
		}
	}
	return guides, nil
}

func loadLocalRoot(ctx context.Context, root *os.Root) ([]LocalGuide, error) {
	entries, err := fs.ReadDir(root.FS(), ".")
	if err != nil {
		return nil, err
	}
	var guides []LocalGuide
	for _, entry := range entries {
		if entry.Type()&fs.ModeSymlink != 0 {
			return nil, ErrLocalSkills
		}
		if !entry.IsDir() {
			continue
		}
		if !localSkillName.MatchString(entry.Name()) {
			return nil, ErrLocalSkills
		}
		snapshot := fstest.MapFS{}
		total := 0
		err = fs.WalkDir(root.FS(), entry.Name(), func(name string, d fs.DirEntry, walkErr error) error {
			if walkErr != nil || ctx.Err() != nil || d.Type()&fs.ModeSymlink != 0 {
				return ErrLocalSkills
			}
			if d.IsDir() {
				return nil
			}
			if !d.Type().IsRegular() || len(snapshot) >= 64 {
				return ErrLocalSkills
			}
			file, err := root.Open(name)
			if err != nil {
				return ErrLocalSkills
			}
			data, err := io.ReadAll(io.LimitReader(file, 256*1024+1))
			file.Close()
			if err != nil || len(data) > 256*1024 {
				return ErrLocalSkills
			}
			total += len(data)
			if total > 1024*1024 {
				return ErrLocalSkills
			}
			relative, err := filepath.Rel(entry.Name(), name)
			if err != nil {
				return ErrLocalSkills
			}
			snapshot[filepath.ToSlash(relative)] = &fstest.MapFile{Data: data, Mode: 0600}
			return nil
		})
		if err != nil || snapshot["SKILL.md"] == nil {
			return nil, ErrLocalSkills
		}
		uri := "skill://" + entry.Name() + "/SKILL.md"
		compiled, err := (skillformat.Compiler{Source: snapshot}).Compile(ctx, uri)
		if err != nil {
			return nil, ErrLocalSkills
		}
		guides = append(guides, LocalGuide{Compiled: compiled, EntrypointText: string(snapshot["SKILL.md"].Data)})
	}
	return guides, nil
}
