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

package db

import (
	"gorm.io/driver/mysql"
	"gorm.io/gorm"
	gormopentracing "gorm.io/plugin/opentracing"

	"github.com/authboot/authboot-server/pkg/constants"
)

var DB *gorm.DB

// Package-level default DAOs bound to the global connection. Use these for
// ordinary (non-transactional) access, e.g. db.IUserDAO.CreateUser(u). For a
// transaction, call DB.Transaction and use IUserDAO.WithTx(tx) / IUserIdentityDAO.WithTx(tx)
// so the writes share one tx.
var (
	IUserDAO                   *UserDAO
	IUserIdentityDAO           *UserIdentityDAO
	IOrganizationDAO           *OrganizationDAO
	IOAuthConfigDAO            *OAuthConfigDAO
	IMessageProviderConfigDAO  *MessageProviderConfigDAO
	IEmailTemplateDAO          *EmailTemplateDAO
	INotificationDAO           *NotificationDAO
	IOrganizationInvitationDAO *OrganizationInvitationDAO
	IOrganizationMembershipDAO *OrganizationMembershipDAO
)

// Init init DB
func Init() {
	var err error
	DB, err = gorm.Open(mysql.Open(constants.GetMySQLDSN()),
		&gorm.Config{
			PrepareStmt:            true,
			SkipDefaultTransaction: true,
		},
	)
	if err != nil {
		panic(err)
	}

	if err = DB.Use(gormopentracing.New()); err != nil {
		panic(err)
	}

	// bind the package-level default DAOs to the global connection.
	IUserDAO = NewUserDAO(DB)
	IUserIdentityDAO = NewUserIdentityDAO(DB)
	IOrganizationDAO = NewOrganizationDAO(DB)
	IOAuthConfigDAO = NewOAuthConfigDAO(DB)
	IMessageProviderConfigDAO = NewMessageProviderConfigDAO(DB)
	IEmailTemplateDAO = NewEmailTemplateDAO(DB)
	INotificationDAO = NewNotificationDAO(DB)
	IOrganizationInvitationDAO = NewOrganizationInvitationDAO(DB)
	IOrganizationMembershipDAO = NewOrganizationMembershipDAO(DB)

	// auto-create / migrate the auth-platform tables.
	if err = DB.AutoMigrate(
		&Organization{},
		&OrganizationMembership{},
		&OrganizationInvitation{},
		&Notification{},
		&User{},
		&UserIdentity{},
		&OAuthConfig{},
		&MessageProviderConfig{},
		&EmailTemplate{},
		&AdminAuditLog{},
		&UserAddress{},
		&UserLoginLog{},
		&AppClient{},
		&AdminUser{},
		&AdminMFA{},
		&AdminMFARecovery{},
		&AdminMFAChallenge{},
		&SecurityGrant{},
		&RevocationOutbox{},
		// admin / user symmetric security tables
		&AdminLoginLog{},
		&UserAuditLog{},
		&AdminSessionRow{},
		&UserSessionRow{},
		&AdminDevice{},
		&UserDevice{},
		&UserSecurityEvent{},
		&OrganizationLegalDocVersion{},
	); err != nil {
		panic(err)
	}
}
