package screenshots

import (
	"bytes"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"fmt"
	"image"
	"image/jpeg"
	_ "image/png"
	"net/http"
	"os"
	"path/filepath"
	"regexp"

	"golang.org/x/image/draw"
)

const (
	MaxBytes   = 5 << 20
	MaxWidth   = 8000
	MaxHeight  = 8000
	ThumbWidth = 320
)

var hexName = regexp.MustCompile(`^[0-9a-f]{64}$`)

type Store struct {
	dir   string
	write *sql.DB
}

func New(dir string, write *sql.DB) (*Store, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}

	if err := os.MkdirAll(filepath.Join(dir, "thumbs"), 0o700); err != nil {
		return nil, err
	}
	return &Store{dir: dir, write: write}, nil
}

func (st *Store) Put(data []byte) (sha string, existed bool, err error) {
	if len(data) == 0 {
		return "", false, fmt.Errorf("screenshots: empty upload")
	}
	if len(data) > MaxBytes {
		return "", false, fmt.Errorf("screenshots: file exceeds 5 MB")
	}
	kind := http.DetectContentType(data)
	if kind != "image/jpeg" && kind != "image/png" {
		return "", false, fmt.Errorf("screenshots: only PNG and JPEG are accepted (got %s)", kind)
	}
	cfg, _, err := image.DecodeConfig(bytes.NewReader(data))
	if err != nil {
		return "", false, fmt.Errorf("screenshots: not a decodable image: %v", err)
	}
	if cfg.Width > MaxWidth || cfg.Height > MaxHeight {
		return "", false, fmt.Errorf("screenshots: %dx%d exceeds the %dx%d limit", cfg.Width, cfg.Height, MaxWidth, MaxHeight)
	}
	sum := sha256.Sum256(data)
	sha = hex.EncodeToString(sum[:])
	ext := "png"
	if kind == "image/jpeg" {
		ext = "jpg"
	}
	path := st.path(sha, ext)
	if _, err := os.Stat(path); err == nil {
		return sha, true, nil
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		return "", false, err
	}
	if err := st.writeThumb(sha, ext, data); err != nil {
		return "", false, err
	}
	return sha, false, nil
}

func (st *Store) path(sha, ext string) string {
	return filepath.Join(st.dir, sha+"."+ext)
}

func (st *Store) writeThumb(sha, ext string, data []byte) error {
	img, _, err := image.Decode(bytes.NewReader(data))
	if err != nil {
		return fmt.Errorf("screenshots: decode: %v", err)
	}
	w := img.Bounds().Dx()
	h := img.Bounds().Dy()
	if w <= 0 || h <= 0 {
		return fmt.Errorf("screenshots: image has no pixels")
	}
	tw := ThumbWidth
	if w < tw {
		tw = w
	}
	th := h * tw / w
	if th < 1 {
		th = 1
	}
	dst := image.NewRGBA(image.Rect(0, 0, tw, th))
	draw.ApproxBiLinear.Scale(dst, dst.Bounds(), img, img.Bounds(), draw.Over, nil)
	var buf bytes.Buffer
	if err := jpeg.Encode(&buf, dst, &jpeg.Options{Quality: 75}); err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(st.dir, "thumbs", sha+".jpg"), buf.Bytes(), 0o600)
}

func (st *Store) Open(sha string) (*os.File, string, error) {
	if !hexName.MatchString(sha) {
		return nil, "", os.ErrInvalid
	}
	for ext, typ := range map[string]string{"jpg": "image/jpeg", "png": "image/png"} {
		f, err := os.Open(st.path(sha, ext))
		if err == nil {
			return f, typ, nil
		}
		if !os.IsNotExist(err) {
			return nil, "", err
		}
	}
	return nil, "", os.ErrNotExist
}

func (st *Store) OpenThumb(sha string) (*os.File, error) {
	if !hexName.MatchString(sha) {
		return nil, os.ErrInvalid
	}
	p := filepath.Join(st.dir, "thumbs", sha+".jpg")
	f, err := os.Open(p)
	if err == nil {
		return f, nil
	}
	if !os.IsNotExist(err) {
		return nil, err
	}
	if err := st.regenerateThumb(sha); err != nil {
		return nil, err
	}
	return os.Open(p)
}

func (st *Store) regenerateThumb(sha string) error {
	for _, ext := range []string{"jpg", "png"} {
		data, err := os.ReadFile(st.path(sha, ext))
		if err == nil {
			return st.writeThumb(sha, ext, data)
		}
		if !os.IsNotExist(err) {
			return err
		}
	}
	return os.ErrNotExist
}

func (st *Store) Delete(sha string) {
	if !hexName.MatchString(sha) {
		return
	}
	_ = os.Remove(st.path(sha, "jpg"))
	_ = os.Remove(st.path(sha, "png"))
	_ = os.Remove(filepath.Join(st.dir, "thumbs", sha+".jpg"))
}

func (st *Store) Attach(ref, sha string) error {
	_, err := st.write.Exec(`UPDATE web_results SET screenshot = ?, thumb = ? WHERE screenshot = ?`,
		sha, sha, ref)
	return err
}
