package jwt

import (
	"fmt"
	"reflect"
	"strconv"
	"strings"

	"github.com/cloudwego/hertz/pkg/app"
	"github.com/cloudwego/hertz/pkg/app/server/binding"
	"github.com/cloudwego/hertz/pkg/protocol"
	"github.com/cloudwego/hertz/pkg/route/param"
)

const authorizedOrgKey = "authorized_resource_organization"

// Freeze the authorized selectors, then check the actual decoded request, not
// the spelling or order of input keys. Every current admin handler uses
// BindAndValidate, which calls this Binder before entering the service.
func installAuthorizedBinding(c *app.RequestContext) {
	selectors := make(map[string]string, len(c.Params)+1)
	for _, p := range c.Params {
		selectors[selectorName(p.Key)] = p.Value
	}
	if orgID := c.GetInt64(authorizedOrgKey); orgID > 0 {
		selectors[selectorName("organization_id")] = strconv.FormatInt(orgID, 10)
	}
	c.SetBinder(&authorizedBinder{Binder: binding.DefaultBinder(), selectors: selectors})
}

type authorizedBinder struct {
	binding.Binder
	selectors map[string]string
}

func selectorName(name string) string {
	return strings.ToLower(strings.ReplaceAll(name, "_", ""))
}

func (b *authorizedBinder) check(obj interface{}) error {
	v := reflect.ValueOf(obj)
	if v.Kind() != reflect.Ptr || v.IsNil() || v.Elem().Kind() != reflect.Struct {
		return fmt.Errorf("authorized request must be a struct pointer")
	}
	v = v.Elem()
	t := v.Type()
	for i := 0; i < t.NumField(); i++ {
		field := t.Field(i)
		if field.PkgPath != "" {
			continue
		}
		// Compare the Go field actually consumed by the service. Tags are also
		// recognized for selectors whose Go field has a different name.
		names := []string{field.Name}
		for _, tag := range []string{"path", "json", "query", "form"} {
			names = append(names, strings.Split(field.Tag.Get(tag), ",")[0])
		}
		for _, name := range names {
			expected, exists := b.selectors[selectorName(name)]
			if !exists {
				continue
			}
			value := v.Field(i)
			if value.Kind() == reflect.Ptr {
				if value.IsNil() {
					value.Set(reflect.New(value.Type().Elem()))
				}
				value = value.Elem()
			}
			// Older IDLs lack path tags. If binding left the selector absent,
			// source it from the already-authorized path, never from the client.
			matches := false
			switch value.Kind() {
			case reflect.String:
				if value.IsZero() {
					value.SetString(expected)
				}
				matches = value.String() == expected
			case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
				id, err := strconv.ParseInt(expected, 10, 64)
				if err == nil && value.IsZero() && !value.OverflowInt(id) {
					value.SetInt(id)
				}
				matches = err == nil && value.Int() == id
			case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
				id, err := strconv.ParseUint(expected, 10, 64)
				if err == nil && value.IsZero() && !value.OverflowUint(id) {
					value.SetUint(id)
				}
				matches = err == nil && value.Uint() == id
			}
			if !matches {
				return fmt.Errorf("bound selector does not match authorized resource")
			}
		}
	}
	return nil
}

func (b *authorizedBinder) Bind(req *protocol.Request, obj interface{}, params param.Params) error {
	if err := b.Binder.Bind(req, obj, params); err != nil {
		return err
	}
	return b.check(obj)
}

func (b *authorizedBinder) Validate(req *protocol.Request, obj interface{}) error {
	if err := b.check(obj); err != nil {
		return err
	}
	return b.Binder.Validate(req, obj)
}
