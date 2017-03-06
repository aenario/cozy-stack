package permissions

import (
	"net/http"

	"github.com/cozy/cozy-stack/pkg/consts"
	"github.com/cozy/cozy-stack/pkg/permissions"
	"github.com/cozy/cozy-stack/pkg/vfs"
	"github.com/cozy/cozy-stack/web/middlewares"
	"github.com/labstack/echo"
)

// ErrForbidden is the error returned when permissions does not allow the
// reques.
var ErrForbidden = echo.NewHTTPError(http.StatusForbidden)

// AllowWholeType validates that the context permission set can use a verb on
// the whold doctype
func AllowWholeType(c echo.Context, v permissions.Verb, doctype string) error {
	pdoc, err := getPermission(c)
	if err != nil {
		return err
	}

	if !pdoc.Permissions.AllowWholeType(v, doctype) {
		return ErrForbidden
	}
	return nil
}

// Allow validates the validable object against the context permission set
func Allow(c echo.Context, v permissions.Verb, o permissions.Validable) error {
	pdoc, err := getPermission(c)
	if err != nil {
		return err
	}

	if !pdoc.Permissions.Allow(v, o) {
		return ErrForbidden
	}
	return nil
}

// AllowTypeAndID validates a type & ID against the context permission set
func AllowTypeAndID(c echo.Context, v permissions.Verb, doctype, id string) error {
	pdoc, err := getPermission(c)
	if err != nil {
		return err
	}
	if !pdoc.Permissions.AllowID(v, doctype, id) {
		return ErrForbidden
	}
	return nil
}

// AllowVFS validates a vfs.Validable against the context permission set
func AllowVFS(c echo.Context, v permissions.Verb, o vfs.Validable) error {
	instance := middlewares.GetInstance(c)
	pdoc, err := getPermission(c)
	if err != nil {
		return err
	}
	err = vfs.Allows(instance, *pdoc.Permissions, v, o)
	if err != nil {
		return ErrForbidden
	}
	return nil
}

// AllowInstallApp checks that the current context is tied to the store app,
// which is the only app authorized to install or update other apps.
// It also allow the cozy-stack apps commands to work (CLI).
func AllowInstallApp(c echo.Context, v permissions.Verb) error {
	pdoc, err := getPermission(c)
	if err != nil {
		return err
	}
	sourceID := consts.Apps + "/" + consts.StoreSlug
	switch pdoc.Type {
	case permissions.TypeCLI:
		// OK
	case permissions.TypeApplication:
		if pdoc.SourceID != sourceID {
			return ErrForbidden
		}
	default:
		return ErrForbidden
	}
	if !pdoc.Permissions.AllowWholeType(v, consts.Apps) {
		return ErrForbidden
	}
	return nil
}

// AllowLogout checks if the current permission allows loging out.
// all apps can trigger a logout.
func AllowLogout(c echo.Context) bool {
	pdoc, err := getPermission(c)
	if err != nil {
		return false
	}
	return pdoc.Type == permissions.TypeApplication
}
