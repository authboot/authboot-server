#!/bin/sh

if [ "$1" = "init" ]; then
    hz new -mod github.com/authboot/authboot-server

fi

hz update -idl idl/oauth.proto

# hz update -idl idl/account.proto
# hz update -idl idl/auth.proto
# hz update -idl idl/common.proto
# hz update -idl idl/invitation.proto
# hz update -idl idl/membership.proto
# hz update -idl idl/organization.proto
# hz update -idl idl/rbac.proto
# hz update -idl idl/session.proto
# hz update -idl idl/user.proto
