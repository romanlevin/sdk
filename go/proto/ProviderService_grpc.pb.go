// Code generated by protoc-gen-go-grpc. DO NOT EDIT.

package sdk

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

// ProviderClient is the client API for Provider service.
//
// For semantics around ctx use and closing/ending streaming RPCs, please refer to https://pkg.go.dev/google.golang.org/grpc/?tab=doc#ClientConn.NewStream.
type ProviderClient interface {
	//   rpc CreateOrganization(CreateOrganizationRequest) returns (CreateOrganizationResponse);
	Invite(ctx context.Context, in *InviteRequest, opts ...grpc.CallOption) (*InviteResponse, error)
	InviteWithWorkflow(ctx context.Context, in *InviteRequest, opts ...grpc.CallOption) (*InviteResponse, error)
	InvitationStatus(ctx context.Context, in *InvitationStatusRequest, opts ...grpc.CallOption) (*InvitationStatusResponse, error)
}

type providerClient struct {
	cc grpc.ClientConnInterface
}

func NewProviderClient(cc grpc.ClientConnInterface) ProviderClient {
	return &providerClient{cc}
}

func (c *providerClient) Invite(ctx context.Context, in *InviteRequest, opts ...grpc.CallOption) (*InviteResponse, error) {
	out := new(InviteResponse)
	err := c.cc.Invoke(ctx, "/trinsic.services.Provider/Invite", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *providerClient) InviteWithWorkflow(ctx context.Context, in *InviteRequest, opts ...grpc.CallOption) (*InviteResponse, error) {
	out := new(InviteResponse)
	err := c.cc.Invoke(ctx, "/trinsic.services.Provider/InviteWithWorkflow", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *providerClient) InvitationStatus(ctx context.Context, in *InvitationStatusRequest, opts ...grpc.CallOption) (*InvitationStatusResponse, error) {
	out := new(InvitationStatusResponse)
	err := c.cc.Invoke(ctx, "/trinsic.services.Provider/InvitationStatus", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// ProviderServer is the server API for Provider service.
// All implementations must embed UnimplementedProviderServer
// for forward compatibility
type ProviderServer interface {
	//   rpc CreateOrganization(CreateOrganizationRequest) returns (CreateOrganizationResponse);
	Invite(context.Context, *InviteRequest) (*InviteResponse, error)
	InviteWithWorkflow(context.Context, *InviteRequest) (*InviteResponse, error)
	InvitationStatus(context.Context, *InvitationStatusRequest) (*InvitationStatusResponse, error)
	mustEmbedUnimplementedProviderServer()
}

// UnimplementedProviderServer must be embedded to have forward compatible implementations.
type UnimplementedProviderServer struct {
}

func (UnimplementedProviderServer) Invite(context.Context, *InviteRequest) (*InviteResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method Invite not implemented")
}
func (UnimplementedProviderServer) InviteWithWorkflow(context.Context, *InviteRequest) (*InviteResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method InviteWithWorkflow not implemented")
}
func (UnimplementedProviderServer) InvitationStatus(context.Context, *InvitationStatusRequest) (*InvitationStatusResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method InvitationStatus not implemented")
}
func (UnimplementedProviderServer) mustEmbedUnimplementedProviderServer() {}

// UnsafeProviderServer may be embedded to opt out of forward compatibility for this service.
// Use of this interface is not recommended, as added methods to ProviderServer will
// result in compilation errors.
type UnsafeProviderServer interface {
	mustEmbedUnimplementedProviderServer()
}

func RegisterProviderServer(s grpc.ServiceRegistrar, srv ProviderServer) {
	s.RegisterService(&Provider_ServiceDesc, srv)
}

func _Provider_Invite_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(InviteRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(ProviderServer).Invite(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/trinsic.services.Provider/Invite",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(ProviderServer).Invite(ctx, req.(*InviteRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _Provider_InviteWithWorkflow_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(InviteRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(ProviderServer).InviteWithWorkflow(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/trinsic.services.Provider/InviteWithWorkflow",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(ProviderServer).InviteWithWorkflow(ctx, req.(*InviteRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _Provider_InvitationStatus_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(InvitationStatusRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(ProviderServer).InvitationStatus(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/trinsic.services.Provider/InvitationStatus",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(ProviderServer).InvitationStatus(ctx, req.(*InvitationStatusRequest))
	}
	return interceptor(ctx, in, info, handler)
}

// Provider_ServiceDesc is the grpc.ServiceDesc for Provider service.
// It's only intended for direct use with grpc.RegisterService,
// and not to be introspected or modified (even as a copy)
var Provider_ServiceDesc = grpc.ServiceDesc{
	ServiceName: "trinsic.services.Provider",
	HandlerType: (*ProviderServer)(nil),
	Methods: []grpc.MethodDesc{
		{
			MethodName: "Invite",
			Handler:    _Provider_Invite_Handler,
		},
		{
			MethodName: "InviteWithWorkflow",
			Handler:    _Provider_InviteWithWorkflow_Handler,
		},
		{
			MethodName: "InvitationStatus",
			Handler:    _Provider_InvitationStatus_Handler,
		},
	},
	Streams:  []grpc.StreamDesc{},
	Metadata: "ProviderService.proto",
}
