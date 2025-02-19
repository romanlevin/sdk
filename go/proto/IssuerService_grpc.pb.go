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

// CredentialClient is the client API for Credential service.
//
// For semantics around ctx use and closing/ending streaming RPCs, please refer to https://pkg.go.dev/google.golang.org/grpc/?tab=doc#ClientConn.NewStream.
type CredentialClient interface {
	Issue(ctx context.Context, in *IssueRequest, opts ...grpc.CallOption) (*IssueResponse, error)
	CreateProof(ctx context.Context, in *CreateProofRequest, opts ...grpc.CallOption) (*CreateProofResponse, error)
	VerifyProof(ctx context.Context, in *VerifyProofRequest, opts ...grpc.CallOption) (*VerifyProofResponse, error)
	Send(ctx context.Context, in *SendRequest, opts ...grpc.CallOption) (*SendResponse, error)
}

type credentialClient struct {
	cc grpc.ClientConnInterface
}

func NewCredentialClient(cc grpc.ClientConnInterface) CredentialClient {
	return &credentialClient{cc}
}

func (c *credentialClient) Issue(ctx context.Context, in *IssueRequest, opts ...grpc.CallOption) (*IssueResponse, error) {
	out := new(IssueResponse)
	err := c.cc.Invoke(ctx, "/trinsic.services.Credential/Issue", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *credentialClient) CreateProof(ctx context.Context, in *CreateProofRequest, opts ...grpc.CallOption) (*CreateProofResponse, error) {
	out := new(CreateProofResponse)
	err := c.cc.Invoke(ctx, "/trinsic.services.Credential/CreateProof", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *credentialClient) VerifyProof(ctx context.Context, in *VerifyProofRequest, opts ...grpc.CallOption) (*VerifyProofResponse, error) {
	out := new(VerifyProofResponse)
	err := c.cc.Invoke(ctx, "/trinsic.services.Credential/VerifyProof", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *credentialClient) Send(ctx context.Context, in *SendRequest, opts ...grpc.CallOption) (*SendResponse, error) {
	out := new(SendResponse)
	err := c.cc.Invoke(ctx, "/trinsic.services.Credential/Send", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// CredentialServer is the server API for Credential service.
// All implementations must embed UnimplementedCredentialServer
// for forward compatibility
type CredentialServer interface {
	Issue(context.Context, *IssueRequest) (*IssueResponse, error)
	CreateProof(context.Context, *CreateProofRequest) (*CreateProofResponse, error)
	VerifyProof(context.Context, *VerifyProofRequest) (*VerifyProofResponse, error)
	Send(context.Context, *SendRequest) (*SendResponse, error)
	mustEmbedUnimplementedCredentialServer()
}

// UnimplementedCredentialServer must be embedded to have forward compatible implementations.
type UnimplementedCredentialServer struct {
}

func (UnimplementedCredentialServer) Issue(context.Context, *IssueRequest) (*IssueResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method Issue not implemented")
}
func (UnimplementedCredentialServer) CreateProof(context.Context, *CreateProofRequest) (*CreateProofResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method CreateProof not implemented")
}
func (UnimplementedCredentialServer) VerifyProof(context.Context, *VerifyProofRequest) (*VerifyProofResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method VerifyProof not implemented")
}
func (UnimplementedCredentialServer) Send(context.Context, *SendRequest) (*SendResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method Send not implemented")
}
func (UnimplementedCredentialServer) mustEmbedUnimplementedCredentialServer() {}

// UnsafeCredentialServer may be embedded to opt out of forward compatibility for this service.
// Use of this interface is not recommended, as added methods to CredentialServer will
// result in compilation errors.
type UnsafeCredentialServer interface {
	mustEmbedUnimplementedCredentialServer()
}

func RegisterCredentialServer(s grpc.ServiceRegistrar, srv CredentialServer) {
	s.RegisterService(&Credential_ServiceDesc, srv)
}

func _Credential_Issue_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(IssueRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(CredentialServer).Issue(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/trinsic.services.Credential/Issue",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(CredentialServer).Issue(ctx, req.(*IssueRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _Credential_CreateProof_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(CreateProofRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(CredentialServer).CreateProof(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/trinsic.services.Credential/CreateProof",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(CredentialServer).CreateProof(ctx, req.(*CreateProofRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _Credential_VerifyProof_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(VerifyProofRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(CredentialServer).VerifyProof(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/trinsic.services.Credential/VerifyProof",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(CredentialServer).VerifyProof(ctx, req.(*VerifyProofRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _Credential_Send_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(SendRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(CredentialServer).Send(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/trinsic.services.Credential/Send",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(CredentialServer).Send(ctx, req.(*SendRequest))
	}
	return interceptor(ctx, in, info, handler)
}

// Credential_ServiceDesc is the grpc.ServiceDesc for Credential service.
// It's only intended for direct use with grpc.RegisterService,
// and not to be introspected or modified (even as a copy)
var Credential_ServiceDesc = grpc.ServiceDesc{
	ServiceName: "trinsic.services.Credential",
	HandlerType: (*CredentialServer)(nil),
	Methods: []grpc.MethodDesc{
		{
			MethodName: "Issue",
			Handler:    _Credential_Issue_Handler,
		},
		{
			MethodName: "CreateProof",
			Handler:    _Credential_CreateProof_Handler,
		},
		{
			MethodName: "VerifyProof",
			Handler:    _Credential_VerifyProof_Handler,
		},
		{
			MethodName: "Send",
			Handler:    _Credential_Send_Handler,
		},
	},
	Streams:  []grpc.StreamDesc{},
	Metadata: "IssuerService.proto",
}
