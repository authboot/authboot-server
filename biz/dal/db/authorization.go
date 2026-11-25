package db

import (
	"github.com/authboot/authboot-server/pkg/constants"
	"github.com/authboot/authboot-server/pkg/errno"
)

// ActiveSubject is shared by access validation and refresh authentication.
func ActiveSubject(subject string, accountID, orgID int64) error {
	if DB == nil || accountID <= 0 {
		return errno.AuthorizationFailedErr
	}
	if subject == constants.AdminSubject {
		u, err := QueryAdminUserByID(accountID)
		if err != nil || u.Status != constants.StatusEnabled {
			return errno.AuthorizationFailedErr
		}
		if orgID == 0 {
			return nil
		}
		m, err := NewOrganizationMembershipDAO(DB).QueryMembership(orgID, accountID)
		if err != nil || m.Status != MembershipActive {
			return errno.AuthorizationFailedErr
		}
	} else {
		u, err := NewUserDAO(DB).QueryUserByIdInOrg(orgID, accountID)
		if err != nil || u.Status != constants.StatusEnabled {
			return errno.AuthorizationFailedErr
		}
	}
	org, err := NewOrganizationDAO(DB).QueryOrganizationByID(orgID)
	if err != nil || org.Status != constants.StatusEnabled {
		return errno.AuthorizationFailedErr
	}
	return nil
}

// All backend membership roles share admin permissions within their active workspace.
func RoleAllows(role, permission string) bool {
	switch role {
	case "owner", "admin", "member":
		return permission == "resource:read" || permission == "resource:write" || permission == "organization:manage" || permission == "member:manage"
	default:
		return false
	}
}

func AuthorizeOrganization(accountID, orgID int64, permission string) error {
	if orgID <= 0 || ActiveSubject(constants.AdminSubject, accountID, orgID) != nil {
		return errno.AuthorizationFailedErr
	}
	m, err := NewOrganizationMembershipDAO(DB).QueryMembership(orgID, accountID)
	if err != nil || !RoleAllows(m.Role, permission) {
		return errno.AuthorizationFailedErr
	}
	return nil
}
