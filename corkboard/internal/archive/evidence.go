package archive

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
)

func attachmentNames(ctx context.Context, d *sql.DB) ([]string, error) {
	var exists int
	if err := d.QueryRowContext(ctx, "SELECT COUNT(*) FROM sqlite_schema WHERE type='table' AND name='evidence'").Scan(&exists); err != nil {
		return nil, err
	}
	if exists == 0 {
		return nil, nil
	}
	rows, err := d.QueryContext(ctx, "SELECT DISTINCT sha,media_type FROM evidence WHERE media_type<>'external' ORDER BY sha")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var names []string
	for rows.Next() {
		var sha, media string
		if err = rows.Scan(&sha, &media); err != nil {
			return nil, err
		}
		if !regexpHex(sha) {
			return nil, fmt.Errorf("invalid attachment hash")
		}
		var name string
		switch media {
		case "image/png":
			name = "screenshots/" + sha + ".png"
		case "image/jpeg":
			name = "screenshots/" + sha + ".jpg"
		case "text/plain":
			name = "evidence/" + sha + ".txt"
		default:
			return nil, fmt.Errorf("unsupported attachment media type")
		}
		names = append(names, name)
	}
	return names, rows.Err()
}
func pinAttachments(ctx context.Context, d *sql.DB, src Source, stage string) error {
	names, err := attachmentNames(ctx, d)
	if err != nil {
		return err
	}
	for _, name := range names {
		if err = ctx.Err(); err != nil {
			return err
		}
		target := filepath.Join(stage, filepath.FromSlash(name))
		if _, err = os.Lstat(target); err == nil {
			continue
		}
		source := filepath.Join(filepath.Dir(src.DB.Path), filepath.FromSlash(name))
		if screenshotName.MatchString(name) {
			source = filepath.Join(src.Screenshots, filepath.Base(name))
		}
		info, err := os.Lstat(source)
		if err != nil {
			return fmt.Errorf("missing referenced attachment %s: %w", name, err)
		}
		if !info.Mode().IsRegular() {
			return fmt.Errorf("attachment is not a regular file: %s", name)
		}
		if err = os.MkdirAll(filepath.Dir(target), 0700); err != nil {
			return err
		}
		if err = os.Link(source, target); err != nil {
			if err = copyFile(ctx, source, target); err != nil {
				return err
			}
		}
	}
	return nil
}
