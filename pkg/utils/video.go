/*
 * Copyright 2023 CloudWeGo Authors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package utils

import (
	"context"
	"fmt"
	"strings"

	"github.com/cloudwego/hertz/pkg/app"
	"github.com/cloudwego/hertz/pkg/common/hlog"

	"github.com/authboot/authboot-server/biz/mw/minio"
	"github.com/authboot/authboot-server/pkg/constants"
)

// NewFileName Splicing user_id and time to make unique filename
func NewFileName(user_id, time int64) string {
	return fmt.Sprintf("%d.%d", user_id, time)
}

// URLconvert Convert the path in the database into a complete url accessible by the front end
func URLconvert(ctx context.Context, c *app.RequestContext, path string) (fullURL string) {
	if len(path) == 0 {
		return ""
	}
	arr := strings.Split(path, "/")
	u, err := minio.GetObjURL(ctx, arr[0], arr[1])
	if err != nil {
		hlog.CtxInfof(ctx, err.Error())
		return ""
	}
	u.Scheme = string(c.URI().Scheme())
	u.Host = string(c.URI().Host())
	u.Path = "/src" + u.Path
	return u.String()
}

// MinioPublicURL 把 DB 中保存的 "bucket/key" 拼成前端可直接访问的完整地址
// （MINIO_PUBLIC_BASE_URL + 相对路径）。未配置前缀或已是完整 URL 时原样返回。
func MinioPublicURL(key string) string {
	key = strings.TrimSpace(key)
	if key == "" {
		return ""
	}
	base := strings.TrimRight(constants.GetMinioPublicBaseURL(), "/")
	if base == "" || strings.HasPrefix(key, "http://") || strings.HasPrefix(key, "https://") {
		return key
	}
	return base + "/" + strings.TrimLeft(key, "/")
}

// NormalizeMinioRef 是 MinioPublicURL 的逆向操作：前端若把完整地址回传，
// 这里去掉公网前缀再入库，保证 DB 中始终保存 "bucket/key" 相对路径。
func NormalizeMinioRef(ref string) string {
	ref = strings.TrimSpace(ref)
	base := strings.TrimRight(constants.GetMinioPublicBaseURL(), "/")
	if base != "" && strings.HasPrefix(ref, base+"/") {
		return strings.TrimPrefix(ref, base+"/")
	}
	return ref
}
