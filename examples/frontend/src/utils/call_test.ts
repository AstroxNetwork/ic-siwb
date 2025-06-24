import { ActorSubclass, SignIdentity } from "@dfinity/agent";
import { _SERVICE as whoAmIService } from "../idls/who_am_i.d";
import { idlFactory as whoAmIIdlFactory } from "../idls/who_am_i.idl";
import { _createActor, getActor } from "./baseConnection";
import { Principal } from "@dfinity/principal";

export async function whoAmI(whoAmIId: string, identity: SignIdentity): Promise<Principal> {
    const actor: ActorSubclass<whoAmIService> = await getActor<whoAmIService>(
        // use credential identity, owner of canister
        identity,
        // use idlFactory from generated file
        whoAmIIdlFactory,
        // get canister ID for 'popcorn', `configs/popcorn.json` is generated
        whoAmIId,
    );
    const m = await actor.whoAmI();
    return m;
}