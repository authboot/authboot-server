package utils

import (
	"bytes"
	"context"
	"crypto/rand"
	"fmt"
	"image"
	_ "image/gif"
	_ "image/jpeg"
	_ "image/png"
	"io"
	"strings"

	"github.com/cloudwego/hertz/pkg/app"
	miniogo "github.com/minio/minio-go/v7"

	"github.com/authboot/authboot-server/biz/mw/minio"
	"github.com/authboot/authboot-server/pkg/constants"
	"github.com/authboot/authboot-server/pkg/errno"
)

// MaxAvatarBytes is the largest avatar image accepted for upload.
const MaxAvatarBytes = 5 << 20

// AvatarFormField is the multipart field that carries the avatar image.
const AvatarFormField = "avatar"

// ValidateAvatar checks decoded content rather than trusting the filename or MIME header.
func ValidateAvatar(data []byte) (string, error) {
	if len(data) == 0 || len(data) > MaxAvatarBytes {
		return "", errno.ParamErr
	}
	cfg, format, err := image.DecodeConfig(bytes.NewReader(data))
	if err != nil || cfg.Width <= 0 || cfg.Height <= 0 || int64(cfg.Width)*int64(cfg.Height) > 16_000_000 {
		return "", errno.ParamErr
	}
	switch format {
	case "jpeg", "png", "gif":
	default:
		return "", errno.ParamErr
	}
	if _, _, err := image.Decode(bytes.NewReader(data)); err != nil {
		return "", errno.ParamErr
	}
	return format, nil
}

// StoreAvatarUpload reads the multipart "avatar" image from the request,
// validates it and stores it in the image bucket under
// "<keyPrefix>-<random>.<format>". It returns the "bucket/key" reference to
// persist, plus a remove func that deletes the new object again — call it when
// persisting the reference fails, so no orphan is left behind. Shared by the
// end-user and platform-admin avatar uploads.
func StoreAvatarUpload(ctx context.Context, c *app.RequestContext, keyPrefix string) (ref string, remove func(), err error) {
	file, err := c.FormFile(AvatarFormField)
	if err != nil || file.Size <= 0 || file.Size > MaxAvatarBytes {
		return "", nil, errno.ParamErr
	}
	reader, err := file.Open()
	if err != nil {
		return "", nil, err
	}
	defer reader.Close()
	data, err := io.ReadAll(io.LimitReader(reader, MaxAvatarBytes+1))
	if err != nil {
		return "", nil, err
	}
	format, err := ValidateAvatar(data)
	if err != nil {
		return "", nil, err
	}
	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return "", nil, err
	}
	key := fmt.Sprintf("%s-%x.%s", keyPrefix, nonce, format)
	if minio.Client == nil {
		return "", nil, fmt.Errorf("avatar storage is unavailable")
	}
	if _, err := minio.Client.PutObject(ctx, constants.MinioImgBucketName, key,
		bytes.NewReader(data), int64(len(data)), miniogo.PutObjectOptions{ContentType: "image/" + format}); err != nil {
		return "", nil, err
	}
	remove = func() {
		_ = minio.Client.RemoveObject(ctx, constants.MinioImgBucketName, key, miniogo.RemoveObjectOptions{})
	}
	return constants.MinioImgBucketName + "/" + key, remove, nil
}

// AvatarURL preserves externally supplied URLs and turns our stored
// "bucket/key" references into public object URLs (MINIO_PUBLIC_BASE_URL),
// the same way organization logos are exposed.
func AvatarURL(avatar string) string {
	if strings.HasPrefix(avatar, constants.MinioImgBucketName+"/") {
		return MinioPublicURL(avatar)
	}
	return avatar
}
