// Code generated by protoc-gen-go-grpc. DO NOT EDIT.
// versions:
// - protoc-gen-go-grpc v1.3.0
// - protoc             v3.21.10
// source: v1/license/license.proto

package license

import (
	context "context"
	grpc "google.golang.org/grpc"
	codes "google.golang.org/grpc/codes"
	status "google.golang.org/grpc/status"
)

// This is a compile-time assertion to ensure that this generated file
// is compatible with the grpc package it is being compiled against.
// Requires gRPC-Go v1.32.0 or later.
const _ = grpc.SupportPackageIsVersion7

const (
	License_InstallLicense_FullMethodName   = "/v1.license.License/InstallLicense"
	License_GetLicenseStatus_FullMethodName = "/v1.license.License/GetLicenseStatus"
)

// LicenseClient is the client API for License service.
//
// For semantics around ctx use and closing/ending streaming RPCs, please refer to https://pkg.go.dev/google.golang.org/grpc/?tab=doc#ClientConn.NewStream.
type LicenseClient interface {
	InstallLicense(ctx context.Context, in *LicenseInstallRequest, opts ...grpc.CallOption) (*LicenseInstallResponse, error)
	GetLicenseStatus(ctx context.Context, in *LicenseStatusRequest, opts ...grpc.CallOption) (*LicenseStatusResponse, error)
}

type licenseClient struct {
	cc grpc.ClientConnInterface
}

func NewLicenseClient(cc grpc.ClientConnInterface) LicenseClient {
	return &licenseClient{cc}
}

func (c *licenseClient) InstallLicense(ctx context.Context, in *LicenseInstallRequest, opts ...grpc.CallOption) (*LicenseInstallResponse, error) {
	out := new(LicenseInstallResponse)
	err := c.cc.Invoke(ctx, License_InstallLicense_FullMethodName, in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *licenseClient) GetLicenseStatus(ctx context.Context, in *LicenseStatusRequest, opts ...grpc.CallOption) (*LicenseStatusResponse, error) {
	out := new(LicenseStatusResponse)
	err := c.cc.Invoke(ctx, License_GetLicenseStatus_FullMethodName, in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// LicenseServer is the server API for License service.
// All implementations must embed UnimplementedLicenseServer
// for forward compatibility
type LicenseServer interface {
	InstallLicense(context.Context, *LicenseInstallRequest) (*LicenseInstallResponse, error)
	GetLicenseStatus(context.Context, *LicenseStatusRequest) (*LicenseStatusResponse, error)
	mustEmbedUnimplementedLicenseServer()
}

// UnimplementedLicenseServer must be embedded to have forward compatible implementations.
type UnimplementedLicenseServer struct {
}

func (UnimplementedLicenseServer) InstallLicense(context.Context, *LicenseInstallRequest) (*LicenseInstallResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method InstallLicense not implemented")
}
func (UnimplementedLicenseServer) GetLicenseStatus(context.Context, *LicenseStatusRequest) (*LicenseStatusResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method GetLicenseStatus not implemented")
}
func (UnimplementedLicenseServer) mustEmbedUnimplementedLicenseServer() {}

// UnsafeLicenseServer may be embedded to opt out of forward compatibility for this service.
// Use of this interface is not recommended, as added methods to LicenseServer will
// result in compilation errors.
type UnsafeLicenseServer interface {
	mustEmbedUnimplementedLicenseServer()
}

func RegisterLicenseServer(s grpc.ServiceRegistrar, srv LicenseServer) {
	s.RegisterService(&License_ServiceDesc, srv)
}

func _License_InstallLicense_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(LicenseInstallRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(LicenseServer).InstallLicense(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: License_InstallLicense_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(LicenseServer).InstallLicense(ctx, req.(*LicenseInstallRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _License_GetLicenseStatus_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(LicenseStatusRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(LicenseServer).GetLicenseStatus(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: License_GetLicenseStatus_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(LicenseServer).GetLicenseStatus(ctx, req.(*LicenseStatusRequest))
	}
	return interceptor(ctx, in, info, handler)
}

// License_ServiceDesc is the grpc.ServiceDesc for License service.
// It's only intended for direct use with grpc.RegisterService,
// and not to be introspected or modified (even as a copy)
var License_ServiceDesc = grpc.ServiceDesc{
	ServiceName: "v1.license.License",
	HandlerType: (*LicenseServer)(nil),
	Methods: []grpc.MethodDesc{
		{
			MethodName: "InstallLicense",
			Handler:    _License_InstallLicense_Handler,
		},
		{
			MethodName: "GetLicenseStatus",
			Handler:    _License_GetLicenseStatus_Handler,
		},
	},
	Streams:  []grpc.StreamDesc{},
	Metadata: "v1/license/license.proto",
}
