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

package email

import (
	"bytes"
	"embed"
	"fmt"
	"html/template"
)

// templateFS embeds the HTML email templates so they ship inside the binary
// and need no runtime file paths.
//
//go:embed templates/*.html
var templateFS embed.FS

// templates holds every parsed template, keyed by its file base name
// (e.g. "invitation.html").
var templates = template.Must(template.ParseFS(templateFS, "templates/*.html"))

// Render executes the named email template with data and returns the rendered
// HTML. name is the template file's base name, e.g. "invitation.html".
func Render(name string, data any) (string, error) {
	var buf bytes.Buffer
	if err := templates.ExecuteTemplate(&buf, name, data); err != nil {
		return "", fmt.Errorf("email: render template %q: %w", name, err)
	}
	return buf.String(), nil
}
