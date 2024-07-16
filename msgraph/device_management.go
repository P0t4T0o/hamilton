package msgraph

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"github.com/hashicorp/go-azure-sdk/sdk/odata"
)

type DeviceManagementClient struct {
	BaseClient Client
}

// NewDeviceManagementClient returns a new DeviceManagementClient.
func NewDeviceManagementClient() *DeviceManagementClient {
	return &DeviceManagementClient{
		BaseClient: NewClient(VersionBeta),
	}
}

// Create creates a new device management object.
func (c *DeviceManagementClient) Get(ctx context.Context, id string, query odata.Query) (*DeviceManagement, int, error) {
	var status int

	resp, status, _, err := c.BaseClient.Get(ctx, GetHttpRequestInput{
		ValidStatusCodes: []int{http.StatusOK},
		OData:            query,
		Uri: Uri{
			Entity: "/deviceManagement",
		},
	})
	if err != nil {
		return nil, status, fmt.Errorf("DeviceManagementClient.BaseClient.Get(): %v", err)
	}

	defer resp.Body.Close()
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, status, fmt.Errorf("io.ReadAll(): %v", err)
	}

	var newDm DeviceManagement
	if err := json.Unmarshal(respBody, &newDm); err != nil {
		return nil, status, fmt.Errorf("json.Unmarshal(): %v", err)
	}

	return &newDm, status, err
}

// Update updates a device management object.
func (c *DeviceManagementClient) Update(ctx context.Context, dmReqBody DeviceManagement) (*DeviceManagement, int, error) {
	var status int

	body, err := json.Marshal(dmReqBody)
	if err != nil {
		return nil, status, fmt.Errorf("json.Marshal(): %v", err)
	}

	resp, status, _, err := c.BaseClient.Patch(ctx, PatchHttpRequestInput{
		ValidStatusCodes: []int{http.StatusOK},
		Uri: Uri{
			Entity: "/deviceManagement",
		},
		Body: body,
	})
	if err != nil {
		return nil, status, fmt.Errorf("DeviceManagementClient.BaseClient.Patch(): %v", err)
	}

	defer resp.Body.Close()
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, status, fmt.Errorf("io.ReadAll(): %v", err)
	}

	var newDm DeviceManagement
	if err := json.Unmarshal(respBody, &newDm); err != nil {
		return nil, status, fmt.Errorf("json.Unmarshal(): %v", err)
	}

	return &newDm, status, err
}
