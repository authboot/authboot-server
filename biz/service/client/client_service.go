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

// Package client implements the admin-side CRUD for an organization's product
// clients (iOS / Android / H5 / mini-program ...). Every operation is scoped to
// the organization in the route path.
package client

import (
	"context"

	"github.com/cloudwego/hertz/pkg/app"

	"github.com/authboot/authboot-server/biz/dal/db"
	"github.com/authboot/authboot-server/biz/model/client"
	"github.com/authboot/authboot-server/biz/model/common"
	"github.com/authboot/authboot-server/pkg/constants"
	"github.com/authboot/authboot-server/pkg/errno"
)

const (
	defaultPageSize = 20
	maxPageSize     = 100
)

// ClientService manages an organization's product clients.
type ClientService struct {
	ctx context.Context
	c   *app.RequestContext

	clientDAO *db.AppClientDAO
}

// NewClientService creates a client management service.
func NewClientService(ctx context.Context, c *app.RequestContext) *ClientService {
	return &ClientService{
		ctx:       ctx,
		c:         c,
		clientDAO: db.NewAppClientDAO(db.DB),
	}
}

// CreateClient registers a new client under an organization.
func (s *ClientService) CreateClient(req *client.CreateClientRequest) (*client.CreateClientResponse, error) {
	if req.OrganizationId == 0 || req.Name == "" {
		return nil, errno.ParamErr
	}
	c := &db.AppClient{
		OrganizationID: req.OrganizationId,
		Name:           req.Name,
		ClientType:     int32(req.ClientType),
		Status:         constants.StatusEnabled,
	}
	id, err := s.clientDAO.Create(c)
	if err != nil {
		return nil, err
	}
	c.ID = id
	return &client.CreateClientResponse{
		Code:    errno.SuccessCode,
		Message: errno.SuccessMsg,
		Client:  toClientInfo(c),
	}, nil
}

// GetClient returns one client of an organization.
func (s *ClientService) GetClient(req *client.GetClientRequest) (*client.GetClientResponse, error) {
	if req.OrganizationId == 0 || req.ClientId == 0 {
		return nil, errno.ParamErr
	}
	c, err := s.clientDAO.QueryByIDInOrg(req.OrganizationId, req.ClientId)
	if err != nil {
		return nil, err
	}
	return &client.GetClientResponse{
		Code:    errno.SuccessCode,
		Message: errno.SuccessMsg,
		Client:  toClientInfo(c),
	}, nil
}

// ListClients returns a page of an organization's clients.
func (s *ClientService) ListClients(req *client.ListClientsRequest) (*client.ListClientsResponse, error) {
	if req.OrganizationId == 0 {
		return nil, errno.ParamErr
	}
	page, pageSize := normalizePaging(req.Page, req.PageSize)
	clients, total, err := s.clientDAO.ListByOrg(req.OrganizationId, (page-1)*pageSize, pageSize)
	if err != nil {
		return nil, err
	}
	infos := make([]*client.AppClient, 0, len(clients))
	for _, c := range clients {
		infos = append(infos, toClientInfo(c))
	}
	return &client.ListClientsResponse{
		Code:    errno.SuccessCode,
		Message: errno.SuccessMsg,
		Clients: infos,
		Total:   total,
	}, nil
}

// UpdateClient updates a client's name / type / status. Zero-valued request
// fields are left unchanged.
func (s *ClientService) UpdateClient(req *client.UpdateClientRequest) (*client.UpdateClientResponse, error) {
	if req.OrganizationId == 0 || req.ClientId == 0 {
		return nil, errno.ParamErr
	}
	c, err := s.clientDAO.QueryByIDInOrg(req.OrganizationId, req.ClientId)
	if err != nil {
		return nil, err
	}
	if req.Name != "" {
		c.Name = req.Name
	}
	if req.ClientType != common.ClientType_CLIENT_TYPE_UNKNOWN {
		c.ClientType = int32(req.ClientType)
	}
	if req.Status != common.Status_STATUS_UNKNOWN {
		c.Status = int8(req.Status)
	}
	if err := s.clientDAO.Update(c); err != nil {
		return nil, err
	}
	return &client.UpdateClientResponse{
		Code:    errno.SuccessCode,
		Message: errno.SuccessMsg,
		Client:  toClientInfo(c),
	}, nil
}

// DeleteClient removes a client from an organization.
func (s *ClientService) DeleteClient(req *client.DeleteClientRequest) (*client.DeleteClientResponse, error) {
	if req.OrganizationId == 0 || req.ClientId == 0 {
		return nil, errno.ParamErr
	}
	if err := s.clientDAO.Delete(req.OrganizationId, req.ClientId); err != nil {
		return nil, err
	}
	return &client.DeleteClientResponse{Code: errno.SuccessCode, Message: errno.SuccessMsg}, nil
}

// toClientInfo maps a db client row to the API view.
func toClientInfo(c *db.AppClient) *client.AppClient {
	return &client.AppClient{
		Id:             c.ID,
		OrganizationId: c.OrganizationID,
		Name:           c.Name,
		ClientType:     common.ClientType(c.ClientType),
		Status:         common.Status(c.Status),
		CreatedAt:      c.CreatedAt,
		UpdatedAt:      c.UpdatedAt,
	}
}

// normalizePaging clamps page/page_size into sane bounds.
func normalizePaging(page, pageSize int32) (int, int) {
	p := int(page)
	if p < 1 {
		p = 1
	}
	ps := int(pageSize)
	if ps < 1 {
		ps = defaultPageSize
	}
	if ps > maxPageSize {
		ps = maxPageSize
	}
	return p, ps
}
