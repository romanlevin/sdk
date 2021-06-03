const test = require("ava");
const { TrinsicProviderService } = require("../dist/ProviderService.js");
const { InviteRequest, InvitationStatusRequest, InvitationStatusResponse } = require('../dist/proto/ProviderService_pb');
const { TrinsicWalletService } = require("../dist/WalletService.js");
const { WalletProfile } = require("../dist/proto/WalletService_pb.js");
const { Struct } = require('google-protobuf/google/protobuf/struct_pb');
const fs = require("fs");
const path = require("path");

const createProfile = async () => {
  // if you have a profile saved
  let homePath = process.env[(process.platform === 'win32') ? 'USERPROFILE' : 'HOME']
  let profilePath = path.join(homePath, '.trinsic', 'profile.bin');

  let profileJSON = JSON.parse(fs.readFileSync(profilePath));
  let profile = new WalletProfile();
  profile.setCapability(profileJSON.capability);
  profile.setDidDocument(Struct.fromJavaScript(profile.didDocument));
  profile.setInvoker(profileJSON.invoker);
  profile.setInvokerJwk(profileJSON.invokerJwk);
  profile.setWalletId(profileJSON.walletId);

  // // if you don't have a profile saved
  // let walletService = new TrinsicWalletService();
  // let profile = await walletService.createWallet()

  return profile;
}

test("make an invitation", async t => {
  let providerService = new TrinsicProviderService();
  let profile = await createProfile();
  providerService.setProfile(profile);
  let inviteRequest = new InviteRequest();
  inviteRequest.setEmail("michael.black@trinsic.id");
  inviteRequest.setDescription("invitation");

  let inviteResponse = await providerService.inviteParticipant(inviteRequest);

  t.not(inviteResponse, null);
  t.not(inviteResponse.getInvitationId(), null);
  t.pass();
});
