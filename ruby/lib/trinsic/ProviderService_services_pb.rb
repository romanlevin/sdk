# Generated by the protocol buffer compiler.  DO NOT EDIT!
# Source: ProviderService.proto for package 'trinsic.services'

require 'grpc'
require 'ProviderService_pb'

module Trinsic
  module Services
    module Provider
      class Service

        include ::GRPC::GenericService

        self.marshal_class_method = :encode
        self.unmarshal_class_method = :decode
        self.service_name = 'trinsic.services.Provider'

        #   rpc CreateOrganization(CreateOrganizationRequest) returns (CreateOrganizationResponse);
        rpc :Invite, ::Trinsic::Services::InviteRequest, ::Trinsic::Services::InviteResponse
        rpc :InviteWithWorkflow, ::Trinsic::Services::InviteRequest, ::Trinsic::Services::InviteResponse
        rpc :InvitationStatus, ::Trinsic::Services::InvitationStatusRequest, ::Trinsic::Services::InvitationStatusResponse
        #   rpc CreateCredentialTemplate(CreateCredentialTemplateRequest) returns (CreateCredentialTemplateResponse);
        #   rpc ListCredentialTemplates(ListCredentialTemplatesRequest) returns (ListCredentialTemplatesResponse);
      end

      Stub = Service.rpc_stub_class
    end
  end
end
