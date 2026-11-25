package utils

import (
	"bytes"
	"errors"
	"image"
	"image/gif"
	"image/jpeg"
	"image/png"
	"testing"

	"github.com/authboot/authboot-server/pkg/errno"
)

func TestValidateAvatar(t *testing.T) {
	img := image.NewRGBA(image.Rect(0, 0, 2, 2))
	for _, format := range []string{"png", "jpeg", "gif"} {
		t.Run(format, func(t *testing.T) {
			var b bytes.Buffer
			var err error
			switch format {
			case "png":
				err = png.Encode(&b, img)
			case "jpeg":
				err = jpeg.Encode(&b, img, nil)
			case "gif":
				err = gif.Encode(&b, img, nil)
			}
			if err != nil {
				t.Fatal(err)
			}
			got, err := ValidateAvatar(b.Bytes())
			if err != nil || got != format {
				t.Fatalf("format=%q err=%v", got, err)
			}
			if _, err := ValidateAvatar(b.Bytes()[:b.Len()/2]); err == nil {
				t.Fatal("accepted truncated image")
			}
		})
	}
	var large bytes.Buffer
	if err := png.Encode(&large, image.NewGray(image.Rect(0, 0, 4001, 4000))); err != nil {
		t.Fatal(err)
	}
	for name, data := range map[string][]byte{
		"empty": nil, "svg": []byte(`<svg onload="alert(1)"/>`),
		"oversized": make([]byte, MaxAvatarBytes+1), "pixels": large.Bytes(),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := ValidateAvatar(data); !errors.Is(err, errno.ParamErr) {
				t.Fatalf("expected parameter error, got %v", err)
			}
		})
	}
}

func TestAvatarURLUsesMinioPublicBaseURL(t *testing.T) {
	stored := "imagebucket/avatar-1-1-abc.png"
	external := "https://cdn.example.test/a.png"

	t.Setenv("MINIO_PUBLIC_BASE_URL", "http://files.example.test:8998/")
	for input, want := range map[string]string{
		stored:   "http://files.example.test:8998/imagebucket/avatar-1-1-abc.png",
		external: external,
		"":       "",
	} {
		if got := AvatarURL(input); got != want {
			t.Fatalf("AvatarURL(%q) = %q, want %q", input, got, want)
		}
	}

	// Without a public base URL the stored reference is returned unchanged.
	t.Setenv("MINIO_PUBLIC_BASE_URL", "")
	if got := AvatarURL(stored); got != stored {
		t.Fatalf("AvatarURL(%q) = %q, want it unchanged", stored, got)
	}
}
